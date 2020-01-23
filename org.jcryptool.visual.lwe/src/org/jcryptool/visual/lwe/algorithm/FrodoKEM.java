package org.jcryptool.visual.lwe.algorithm;

import java.security.SecureRandom;
import java.util.Arrays;

import org.bouncycastle.crypto.digests.SHAKEDigest;

public class FrodoKEM {

  

    private AlgorithmParameters params;
    private SecureRandom rand;

    byte[] pk, sk;

    private short[] B;
    private short[] S;
    private short[] E;

    private byte[] randomness;
    private byte[] shake_input_seedSE;
    private byte[] pk_seedA;
    private short[] sk_S;

    public static void main(String[] args) {
        FrodoKEM frodo = new FrodoKEM();
    }

    public FrodoKEM() {
        rand = new SecureRandom();
        SHAKEDigest shake = new SHAKEDigest();
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
        params.secretKeyBytes = 43088; // sizeof(s) + CRYPTO_PUBLICKEYBYTES +
        // 2*PARAMS_N*PARAMS_NBAR + BYTES_PKHASH
        params.publicKeyBytes = 21520; // sizeof(seed_A) +
        // (PARAMS_LOGQ*PARAMS_N*PARAMS_NBAR)/8
        
        pk = new byte[params.publicKeyBytes];
        sk = new byte[params.secretKeyBytes];
        //pk_seedA = new byte[CRYPTO_PUBLICKEYBYTES];
        S = new short[2 * params.no * params.nbar];
        B = new short[params.no * params.nbar];
        E = new short[params.no * params.nbar];
        randomness = new byte[2 * params.cryptoBytes + params.lenSeedA];
        shake_input_seedSE = new byte[1 + params.cryptoBytes];
        rand.nextBytes(randomness);

        shake.update(randomness, 2 * params.cryptoBytes, params.lenSeedA);
        shake.doFinal(pk, 0, params.lenSeedA);

        shake_input_seedSE[0] = 0x5F;
        System.arraycopy(randomness, params.cryptoBytes, shake_input_seedSE, 1, params.cryptoBytes);
        shakeToShort(shake_input_seedSE, S);

        S = sampleMatrix(S, S.length);
        System.arraycopy(S, params.no * params.nbar, E, 0, params.no * params.nbar);

        multiplyASplusE(B, S, E, pk);

        byte[] pk_b = pack(B, B.length, (byte) params.logQ);

        // Encode second part of public key
        System.arraycopy(pk_b, 0, pk, params.lenSeedA, pk_b.length);

        //add s, pk and S to secret key
        System.arraycopy(randomness, 0, sk, 0, params.cryptoBytes);
        System.arraycopy(pk, 0, sk, params.cryptoBytes, params.publicKeyBytes);
        
        int j = params.cryptoBytes + params.publicKeyBytes;
        for (int i = 0; i < S.length; i ++) {
            sk[j++] =(byte) (S[i] >> 8);
            sk[j++] = (byte) (S[i] & 0xFF);
        }
              
        shake.update(pk, 0, pk.length);
        shake.doFinal(sk, params.cryptoBytes + params.publicKeyBytes + S.length);

        // *randomness_s = &randomness[0]; // contains secret data
        // *randomness_seedSE = &randomness[CRYPTO_BYTES]; // contains secret data
        // *randomness_z = &randomness[2*CRYPTO_BYTES];
    }

    private void shakeToShort(byte[] input, short[] output) {
        shakeToShort(input, 0, input.length, output, 0, output.length);
    }

    private void shakeToShort(byte[] input, int inOffset, int inlen, short[] output, int outOffset, int outlen) {
        SHAKEDigest d = new SHAKEDigest();
        byte[] temp = new byte[2*outlen];
        d.update(input, inOffset, inlen);
        d.doFinal(temp, 0, temp.length);

        int j = outOffset;
        for (int i = 0; i < temp.length; i += 2) {
            output[j++] = (short) ((temp[i] << 8) | temp[i + 1]);
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
            short prnd = (short) (s[i] >> 1); // Drop the least significant bit
            short sign = (short) (s[i] & 0x1); // Pick the least significant bit

            // No need to compare with the last value.
            for (j = 0; j < (params.CDF_TABLE.length - 1); j++) {
                // Constant time comparison: 1 if CDF_TABLE[j] < s, 0 otherwise. Uses the fact that
                // CDF_TABLE[j] and s fit in 15 bits.
                sample += (short) (params.CDF_TABLE[j] - prnd) >> 15;
            }
            // Assuming that sign is either 0 or 1, flips sample if sign = 1
            r[i] = (short) (((-sign) ^ sample) + sign);
        }
        return r;
    }

    private void multiplyASplusE(short[] out, short[] s, short[] e, byte[] seedA) {
        SHAKEDigest shake = new SHAKEDigest();
        short[] A = new short[params.no * params.no];

        // generate matrix A
        byte seedASeparated[] = new byte[2 + params.lenSeedA];
        System.arraycopy(seedA, 0, seedASeparated, 2, params.lenSeedA);
        for (int i = 0; i < params.no; i++) {
            seedASeparated[0] = (byte) (i & 0xFF);
            seedASeparated[1] = (byte) (i >> 8);
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
    }

    private byte[] pack(short[] input, int inlen, byte lsb) {
        int i = 0; // whole bytes already filled in
        int j = 0; // whole uint16_t already copied
        short w = 0; // the leftover, not yet copied
        byte bits = 0; // the number of lsb in w

        byte[] out = new byte[params.publicKeyBytes - params.lenSeedA];

        while (i < out.length && (j < inlen || ((j == inlen) && (bits > 0)))) {

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
                    if (j < inlen) {
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
