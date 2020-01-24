package org.jcryptool.visual.lwe.algorithm;

import java.security.SecureRandom;
import java.util.Arrays;

import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.eclipse.core.runtime.Assert;

public class FrodoKEM {

    private AlgorithmParameters params;
    private SecureRandom rand;

    byte[] pk, sk;
    private byte[] cyphertext;

    private short[] B;
    private short[] E;
    private byte[] K;

    private short[] S;
    private byte[] randomness;
    private short[] sk_S;

    public static void main(String[] args) {
        FrodoKEM frodo = new FrodoKEM();
        SecureRandom r = new SecureRandom();
        byte[] message = new byte[128 / 8];
        r.nextBytes(message);

        frodo.createKeypair();
        byte[] cypher = frodo.encrypt(message);
        byte[] decoded = frodo.decrypt(cypher);
        // Arrays.asList(cypher).retainAll(Arrays.asList(decoded));
        // assert(cypher.length == 0);
    }

    public FrodoKEM() {
        rand = new SecureRandom();
        // create parameters according to Frodo640 spec
        params = new AlgorithmParameters();

        params.no = 640;
        params.logQ = 15;
        params.q = 1 << params.logQ;
        params.extractedBits = 2;
        params.stripeStep = 8;
        params.nbar = 8;
        params.lenSeedA = 16;
        params.cryptoBytes = 16;
        params.bytesMU = (params.extractedBits * params.nbar * params.nbar) / 8;
        params.CDF_TABLE = new short[] { 4643, 13363, 20579, 25843, 29227, 31145, 32103, 32525, 32689, 32745, 32762,
                32766, 32767 };
        params.secretKeyBytes = 43088; // sizeof(s) + CRYPTO_PUBLICKEYBYTES + 2*PARAMS_N*PARAMS_NBAR
                                       // + BYTES_PKHASH
        params.publicKeyBytes = 21520; // sizeof(seed_A) + (PARAMS_LOGQ*PARAMS_N*PARAMS_NBAR)/8
        params.cypherTextBytes = 9720;
    }

    public void createKeypair() {
        SHAKEDigest shake = new SHAKEDigest();
        pk = new byte[params.publicKeyBytes];
        sk = new byte[params.secretKeyBytes];
        // pk_seedA = new byte[CRYPTO_PUBLICKEYBYTES];
        S = new short[2 * params.no * params.nbar];
        E = new short[params.no * params.nbar];
        randomness = new byte[2 * params.cryptoBytes + params.lenSeedA];
        byte[] shake_input_seedSE = new byte[1 + params.cryptoBytes];
        byte[] pk_seedA = new byte[params.lenSeedA];

        rand.nextBytes(randomness);

        shake.update(randomness, 2 * params.cryptoBytes, params.lenSeedA);
        shake.doFinal(pk_seedA, 0, params.lenSeedA);
        System.arraycopy(pk_seedA, 0, pk, 0, pk_seedA.length);

        shake_input_seedSE[0] = 0x5F;
        System.arraycopy(randomness, params.cryptoBytes, shake_input_seedSE, 1, params.cryptoBytes);
        shakeToShort(shake_input_seedSE, S);

        S = sampleMatrix(S, S.length);
        System.arraycopy(S, params.no * params.nbar, E, 0, params.no * params.nbar);

        B = multiplyASaddE(S, E, pk_seedA);

        byte[] pk_b = pack(B, params.publicKeyBytes - params.lenSeedA, (byte) params.logQ);

        // Encode second part of public key
        System.arraycopy(pk_b, 0, pk, params.lenSeedA, pk_b.length);

        // add s, pk and S to secret key
        System.arraycopy(randomness, 0, sk, 0, params.cryptoBytes);
        System.arraycopy(pk, 0, sk, params.cryptoBytes, params.publicKeyBytes);

        int j = params.cryptoBytes + params.publicKeyBytes;
        for (int i = 0; i < S.length; i++) {
            sk[j++] = (byte) (S[i] >>> 8);
            sk[j++] = (byte) (S[i] & 0xFF);
        }

        shake.update(pk, 0, pk.length);
        shake.doFinal(sk, params.cryptoBytes + params.publicKeyBytes + S.length, params.cryptoBytes);
    }

    private byte[] encrypt(byte[] message) {
        if (message.length != params.bytesMU)
            throw new IllegalArgumentException("Wrong message size, should be " + params.bytesMU);

        short[] Sp = new short[(2 * params.no * params.nbar) * params.nbar];
        short[] Ep = new short[params.no * params.nbar];
        short[] Epp = new short[params.nbar * params.nbar];
        short[] Bp, V, C;
        byte[] G2in = new byte[params.bytesMU + params.cryptoBytes];
        byte[] G2out = new byte[2 * params.cryptoBytes];
        byte[] shake_input_seedSE = new byte[1 + params.cryptoBytes];
        byte[] pkHash = new byte[params.cryptoBytes];
        K = new byte[params.cryptoBytes];
        cyphertext = new byte[params.cypherTextBytes];
        byte[] ct1, ct2;
        // hash public key
        SHAKEDigest shake = new SHAKEDigest();
        shake.update(pk, 0, pk.length);
        shake.doFinal(G2in, 0, params.cryptoBytes);
        System.arraycopy(message, 0, G2in, pkHash.length, message.length);
        shake.update(G2in, 0, G2in.length);
        shake.doFinal(G2out, 0, G2out.length);

        // Generate Sp and Ep, and compute Bp = Sp*A + Ep. Generate A on-the-fly
        shake_input_seedSE[0] = (byte) 0x96;
        System.arraycopy(G2out, 0, shake_input_seedSE, 1, pkHash.length);
        shakeToShort(shake_input_seedSE, Sp);
        sampleMatrix(Sp, Sp.length);
        System.arraycopy(Sp, params.no * params.nbar, Ep, 0, params.no * params.nbar);
        Bp = multiplySAaddE(Sp, Ep, pk);
        ct1 = pack(Bp, (params.logQ*params.no*params.nbar)/8, (byte) params.logQ);

        // Generate Epp, and compute V = Sp*B + Epp
        sampleMatrix(Epp, Epp.length);
        V = muliplySBaddE(B, Sp, Epp);

        // Encode message, and compute C = V + enc(mu) (mod q)
        C = encode(message);
        C = add(C, V);
        
        ct2 = pack(C, (params.logQ*params.nbar*params.nbar)/8, (byte) params.logQ);
        
        System.arraycopy(ct1, 0, cyphertext, 0, ct1.length);
        System.arraycopy(ct2, 0, cyphertext, ct1.length, ct2.length);
      
        return cyphertext;
    }

    private byte[] decrypt(byte[] cyphertext) {
        return new byte[params.secretKeyBytes];
    }

    private void shakeToShort(byte[] input, short[] output) {
        shakeToShort(input, 0, input.length, output, 0, output.length);
    }

    private void shakeToShort(byte[] input, int inOffset, int inlen, short[] output, int outOffset, int outlen) {
        SHAKEDigest d = new SHAKEDigest();
        byte[] temp = new byte[2 * outlen];
        d.update(input, inOffset, inlen);
        d.doFinal(temp, 0, temp.length);

        int j = outOffset;
        for (int i = 0; i < temp.length; i += 2) {
            output[j++] = (short) ((temp[i] << 8) | temp[i + 1] & 0xFF);
        }
    }

    /**
     * Fills a vector with n samples from the noise distribution which requires 16 bits to sample.
     * The distribution is specified by its CDF. Input: pseudo-random values (2*n bytes) passed in
     * s.
     * 
     * @param s vector with pseudo-radomly generated values
     * @param length size of output vector
     * @return vector with sampled values
     **/

    private short[] sampleMatrix(short[] s, int length) {

        int i, j;
        short[] r = new short[s.length];

        for (i = 0; i < length; ++i) {
            short sample = 0;
            short prnd = (short) (s[i] >>> 1); // Drop the least significant bit
            short sign = (short) (s[i] & 0x1); // Pick the least significant bit

            // No need to compare with the last value.
            for (j = 0; j < (params.CDF_TABLE.length - 1); j++) {
                // Constant time comparison: 1 if CDF_TABLE[j] < s, 0 otherwise. Uses the fact that
                // CDF_TABLE[j] and s fit in 15 bits.
                sample += (short) (params.CDF_TABLE[j] - prnd) >>> 15;
            }
            // Assuming that sign is either 0 or 1, flips sample if sign = 1
            r[i] = (short) (((-sign) ^ sample) + sign);
        }
        return r;
    }

    /** Encode a byte string to a m-by-n matrix **/
    private short[] encode(byte[] message) {
        int i, j, npieces_word = 8;
        short[] out = new short[params.nbar * params.nbar];
        int nwords = out.length / 8;
        long temp, mask = (1 << params.extractedBits) - 1;

        for (i = 0; i < nwords; i++) {
            temp = 0;
            for (j = 0; j < params.extractedBits; j++) {
                temp |= (short) (message[i * params.extractedBits + j] << (8 * j)) & 0xFFFF;
            }
            for (j = 0; j < npieces_word; j++) {
                out[i * nwords + j] |= (short) (temp & mask) << (params.logQ - params.extractedBits);
                temp >>>= params.extractedBits;
            }
        }

        return out;
    }

    /**
     * Add matrices a and b (nbar x nbar) 
     * @param a matrix A
     * @param b matrix B
     * @return C = A + B
     **/
    public short[] add(short[] a, short[] b) {
        short[] out = new short[params.nbar * params.nbar];
        for (int i = 0; i < (params.nbar * params.nbar); i++) {
            out[i] = (short) ((a[i] + b[i]) & ((1 << params.logQ) - 1));
        }
        
        return out;
    }

    private short[] multiplyASaddE(short[] s, short[] e, byte[] seedA) {
        short[] out = new short[params.no * params.nbar];
        short[] A = new short[params.no * params.no];

        // generate matrix A
        byte seedASeparated[] = new byte[2 + params.lenSeedA];
        System.arraycopy(seedA, 0, seedASeparated, 2, params.lenSeedA);
        for (int i = 0; i < params.no; i++) {
            seedASeparated[0] = (byte) (i & 0xFF);
            seedASeparated[1] = (byte) (i >>> 8);
            shakeToShort(seedASeparated, 0, seedASeparated.length, A, i * params.no, params.no);
        }

        // Matrix multiplication-addition A*s + e
        for (int i = 0; i < params.no; i++) {
            for (int k = 0; k < params.nbar; k++) {
                short sum = 0;
                for (int j = 0; j < params.no; j++) {
                    sum += A[i * params.no + j] * s[k * params.no + j];
                }
                out[i * params.nbar + k] = (short) (sum + e[i * params.nbar + k]);
            }
        }
        return out;
    }

    /**
     * Generate-and-multiply: generate matrix A (N x N) column-wise, multiply by s' on the left.
     * 
     * @param s the matrix s'
     * @param e the error matrix e'
     * @param seedA the seed for the Matrix A
     * @return out s'*A + e' (N_BAR x N)
     **/
    private short[] multiplySAaddE(short[] s, short[] e, byte[] seedA) {
        short[] out = new short[params.no * params.nbar];
        short[] a_cols = new short[params.no * params.stripeStep];
        int i, colId, j, k, kk, t = 0;

        // generate matrix A column-wise
        byte seedASeparated[] = new byte[2 + params.lenSeedA];
        System.arraycopy(seedA, 0, seedASeparated, 2, params.lenSeedA);
        for (kk = 0; kk < params.no; kk += 4) {
            for (colId = 0; colId < 4; colId++) {
                seedASeparated[0] = (byte) (kk + colId & 0xFF);
                seedASeparated[1] = (byte) (kk + colId >>> 8);
                shakeToShort(seedASeparated, 0, seedASeparated.length, a_cols, colId * params.no, 2 * params.no);
            }

            for (i = 0; i < params.nbar; i++) {

                short[] sum = new short[params.no];
                for (j = 0; j < 4; j++) {
                    short sp = s[i * params.no + kk + j];
                    for (k = 0; k < params.no; k++) { // Matrix-vector multiplication
                        sum[k] += sp * a_cols[(t + j) * params.no + k];
                    }
                }
                for (k = 0; k < params.no; k++) {
                    out[i * params.no + k] += sum[k];
                }
            }
        }
        return out;
    }

    /**
     * Multiply by s on the left Inputs: b (N x N_BAR), s (N_BAR x N), e (N_BAR x N_BAR) Output: out
     * = s*b + e (N_BAR x N_BAR)
     **/
    private short[] muliplySBaddE(short[] b, short[] s, short[] e) {
        int i, j, k;
        short[] out = new short[params.nbar * params.nbar];
        for (k = 0; k < params.nbar; k++) {
            for (i = 0; i < params.nbar; i++) {
                out[k * params.nbar + i] = e[k * params.nbar + i];
                for (j = 0; j < params.no; j++) {
                    out[k * params.nbar + i] += s[k * params.no + j] * b[j * params.nbar + i];
                }
                out[k * params.nbar + i] = (short) (out[k * params.nbar + i] & ((1 << params.logQ) - 1));
            }
        }

        return out;
    }

    private byte[] pack(short[] input, int outlen, byte lsb) {
        int i = 0; // whole bytes already filled in
        int j = 0; // whole uint16_t already copied
        short w = 0; // the leftover, not yet copied
        byte bits = 0; // the number of lsb in w

        byte[] out = new byte[outlen];

        while (i < out.length && (j < input.length || ((j == input.length) && (bits > 0)))) {

            byte b = 0; // bits in out[i] already filled in
            while (b < 8) {
                int nbits = Math.min(8 - b, bits);
                short mask = (short) ((1 << nbits) - 1);
                byte t = (byte) ((w >>> (bits - nbits)) & mask); // the bits to copy from w to out
                out[i] = (byte) (out[i] + (t << (8 - b - nbits)));
                b += nbits;
                bits -= nbits;
                w &= ~(mask << bits); // not strictly necessary; mostly for debugging

                if (bits == 0) {
                    if (j < input.length) {
                        w = input[j];
                        bits = lsb;
                        j++;
                    } else {
                        break; // the input vector is exhausted
                    }
                }
            }
            if (b == 8) { // out[i] is filled in
                i++;
            }
        }

        return out;
    }

}
