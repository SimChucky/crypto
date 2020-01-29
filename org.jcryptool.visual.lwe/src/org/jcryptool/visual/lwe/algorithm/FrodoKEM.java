package org.jcryptool.visual.lwe.algorithm;

import java.security.SecureRandom;
import java.util.Arrays;

import org.bouncycastle.crypto.digests.SHAKEDigest;
import org.eclipse.core.runtime.Assert;

public class FrodoKEM {

    private AlgorithmParameters params;
    private SecureRandom rand;

    private PublicKey pk;
    private SecretKey sk;

    private short[][] CEncode;
    private byte[] CDecode;

    private byte[] cypherText;
    private byte[] mu;

    public static void main(String[] args) {
        FrodoKEM frodo = new FrodoKEM();
        frodo.createKeypair();
                        
        byte[] ss1 = frodo.keyEncap();
        byte[] ss2 = frodo.keyDecap();
        if (!Arrays.equals(ss1, ss2)) {
            throw new RuntimeException("Shared secrets do not match");
        }
        // Arrays.asList(cypher).retainAll(Arrays.asList(decoded));
        // assert(cypher.length == 0);
    }

    public FrodoKEM() {
        rand = new SecureRandom();
        // create parameters according to Frodo640 spec
        params = new AlgorithmParameters();

        params.no = 640;
        params.D = 15;
        params.q = 0x7fff;
        params.B = 2;
        params.stripeStep = 8;
        params.nbar = 8;
        params.lenSeedA = 16;
        params.cryptoBytes = 16;
        params.lenX = 2;
        params.bytesMU = (params.B * params.nbar * params.nbar) / 8;
        params.CDF_TABLE = new int[] { 4643, 13363, 20579, 25843, 29227, 31145, 32103, 32525, 32689, 32745, 32762,
                32766, 32767 };
        params.secretKeyBytes = 19888; // sizeof(s) + CRYPTO_PUBLICKEYBYTES + 2*PARAMS_N*PARAMS_NBAR
                                       // + BYTES_PKHASH
        params.publicKeyBytes = 9616; // sizeof(seed_A) + (PARAMS_LOGQ*PARAMS_N*PARAMS_NBAR)/8
        params.cypherTextBytes = 9720;

        cypherText = new byte[params.cypherTextBytes];

    }

    public void createKeypair() {
        SHAKEDigest shake = new SHAKEDigest();
        byte[] pkBytes = new byte[params.publicKeyBytes];
        short[][] S, E;

        byte[] seed = new byte[2 * params.no * params.nbar * params.lenX];
        byte[] seedS = new byte[params.cryptoBytes];
        byte[] seedSE = new byte[1 + params.cryptoBytes];
        byte[] pkSeedA = new byte[params.lenSeedA];
        byte[] pkHash = new byte[params.cryptoBytes];

        rand.nextBytes(seedSE);
        rand.nextBytes(seedS);
        rand.nextBytes(pkSeedA);

        shake.update(pkSeedA, 0, params.lenSeedA);
        shake.doFinal(pkSeedA, 0, params.lenSeedA);
        System.arraycopy(pkSeedA, 0, pkBytes, 0, pkSeedA.length);

        seedSE[0] = 0x5F;
        shake.update(seedSE, 0, seedSE.length);
        shake.doFinal(seed, 0, seed.length);

        S = sampleMatrix(Arrays.copyOfRange(seed, 0, (seed.length + 1) / 2), params.no, params.nbar);
        E = sampleMatrix(Arrays.copyOfRange(seed, (seed.length + 1) / 2, seed.length), params.no, params.nbar);

        short[][] B = multiplyAddMatrices(genMatrixA(pkSeedA), S, E);
        byte[] pk_b = pack(B);

        // Encode second part of public key
        System.arraycopy(pk_b, 0, pkBytes, params.lenSeedA, pk_b.length);
        shake.update(pkBytes, 0, pkBytes.length);
        shake.doFinal(pkHash, 0, pkHash.length);

        pk = new PublicKey(pkSeedA, pk_b);
        sk = new SecretKey(seedS, S, pkBytes, pkHash);
    }

    /**
     * FrodoKem Key Encapsulation
     * 
     * @param ct buffer array for cyphertext
     * @return the shared secret
     **/
    public byte[] keyEncap() {

        SHAKEDigest shake = new SHAKEDigest();
        byte[] sharedSecret = new byte[params.cryptoBytes];
        
        byte[] seed = new byte[((params.no * params.nbar)*2 + params.nbar * params.nbar)*params.lenX];

        short[][] Sp, Ep, Epp;
        short[][] B, Bp, V, C;
        byte[] G2in = new byte[params.bytesMU + params.cryptoBytes];
        byte[] G2out = new byte[2 * params.cryptoBytes];
        byte[] shakeInputSeedSE = new byte[1 + params.cryptoBytes];
        byte[] pkHash = new byte[params.cryptoBytes];
        byte[] fin = new byte[params.cypherTextBytes + params.cryptoBytes];
        byte[] ct1, ct2;
        mu = new byte[params.bytesMU];
        rand.nextBytes(mu);

        // hash public key
        System.arraycopy(sk.getPkHash(), 0, G2in, 0, sk.getPkHash().length);
        System.arraycopy(mu, 0, G2in, pkHash.length, mu.length);
        shake.update(G2in, 0, G2in.length);
        shake.doFinal(G2out, 0, G2out.length);

        // Generate Sp and Ep, and compute Bp = Sp*A + Ep. Generate A on-the-fly
        shakeInputSeedSE[0] = (byte) 0x96;
        System.arraycopy(G2out, 0, shakeInputSeedSE, 1, pkHash.length);
        shake.update(shakeInputSeedSE, 0, shakeInputSeedSE.length);
        shake.doFinal(seed, 0, seed.length);

        int lenSeed = params.nbar * params.no * params.lenX;
        Sp = sampleMatrix(Arrays.copyOfRange(seed, 0, lenSeed), params.nbar, params.no);
        Ep = sampleMatrix(Arrays.copyOfRange(seed, lenSeed, (lenSeed * 2)), params.nbar, params.no);

        Bp = multiplyAddMatrices(Sp, genMatrixA(pk.getSeedA()), Ep);
        ct1 = pack(Bp);

        // Generate Epp, and compute V = Sp*B + Epp
        Epp = sampleMatrix(Arrays.copyOfRange(seed, lenSeed * 2, seed.length), params.nbar,
                params.nbar);
        B = unpack(pk.getMatrixB(), params.no, params.nbar);
        V = multiplyAddMatrices(Sp, B, Epp);

        // Encode message, and compute C = V + enc(mu) (mod q)
        CEncode = encode(mu);

        CEncode = add(CEncode, V);

        ct2 = pack(CEncode);

        System.arraycopy(ct1, 0, cypherText, 0, ct1.length);
        System.arraycopy(ct2, 0, cypherText, ct1.length, ct2.length);

        System.arraycopy(cypherText, 0, fin, 0, cypherText.length);
        System.arraycopy(G2out, params.cryptoBytes, fin, cypherText.length, params.cryptoBytes);

        shake.update(fin, 0, fin.length);

        shake.doFinal(sharedSecret, 0, sharedSecret.length);

        return sharedSecret;
    }

    private byte[] keyDecap() {
        SHAKEDigest shake = new SHAKEDigest();
        byte[] sharedSecret = new byte[params.cryptoBytes];
        byte[] G2In = new byte[params.cryptoBytes + params.bytesMU];
        byte[] G2Out = new byte[2 * params.cryptoBytes];
        byte[] muPrime = new byte[params.bytesMU];
        byte[] seed = new byte[(2 * params.no + params.nbar) * params.nbar * params.lenX];
        byte[] shakeInputSeedSEprime = new byte[1 + params.cryptoBytes];
        byte[] fin = new byte[params.cypherTextBytes + params.cryptoBytes];
        short[][] B, Bp, BBp, C, CC, W;
        short[][] Sp = new short[params.no][params.nbar];
        short[][] Ep = new short[params.no][params.nbar];
        short[][] Epp = new short[params.nbar][params.nbar];

        // Compute W = C - Bp*S (mod q), and decode the randomness mu
        byte[] ct1 = Arrays.copyOfRange(cypherText, 0, (params.D * params.no * params.nbar) / 8);
        byte[] ct2 = Arrays.copyOfRange(cypherText, (params.D * params.no * params.nbar) / 8, cypherText.length);

        Bp = unpack(ct1, params.nbar, params.no);
        C = unpack(ct2, params.nbar, params.nbar);
      
        W = multiply(Bp, sk.getMatrixS());
        W = sub(C, W);
        muPrime = decode(W);

        // Generate (seedSE' || k') = G_2(pkh || mu')
        System.arraycopy(sk.getPkHash(), 0, G2In, 0, params.cryptoBytes);
        System.arraycopy(muPrime, 0, G2In, params.cryptoBytes, muPrime.length);
        shake.update(G2In, 0, G2In.length);
        shake.doFinal(G2Out, 0, G2Out.length);

        // Generate Sp and Ep, and compute BBp = Sp*A + Ep. Generate A on-the-fly
        shakeInputSeedSEprime[0] = (byte) 0x96;
        System.arraycopy(G2Out, 0, shakeInputSeedSEprime, 1, params.cryptoBytes);
        shake.update(shakeInputSeedSEprime, 0, shakeInputSeedSEprime.length);
        shake.doFinal(seed, 0, seed.length);

        int lenSeed = params.nbar * params.no * params.lenX;
        Sp = sampleMatrix(Arrays.copyOfRange(seed, 0, lenSeed), params.nbar, params.no);
        Ep = sampleMatrix(Arrays.copyOfRange(seed, lenSeed, lenSeed*2), params.nbar, params.no);
        BBp = multiplyAddMatrices(Sp, genMatrixA(pk.getSeedA()), Ep);

        // Generate Epp, and compute W = Sp*B + Epp
        Epp = sampleMatrix(Arrays.copyOfRange(seed, lenSeed * 2, seed.length), params.nbar,
                params.nbar);
        B = unpack(pk.getMatrixB(), params.no, params.nbar);
        W = multiplyAddMatrices(Sp, B, Epp);

        // Encode mu, and compute CC = W + enc(mu') (mod q)
        CC = encode(muPrime);
        CC = add(W, CC);

        System.arraycopy(cypherText, 0, fin, 0, cypherText.length);

        boolean bool1 = Arrays.deepEquals(Bp, BBp);
        
        // Is (Bp == BBp & C == CC) = true
        if (bool1 == true && Arrays.deepEquals(C, CC) == true) {
            // Load k' to do ss = F(ct || k')
            System.arraycopy(G2Out, params.cryptoBytes, fin, params.cypherTextBytes, params.cryptoBytes);
        } else {
            // Load s to do ss = F(ct || s)
            System.arraycopy(sk.getS(), 0, fin, params.cypherTextBytes, params.cryptoBytes);
        }

        shake.update(fin, 0, fin.length);
        shake.doFinal(sharedSecret, 0, params.cryptoBytes);

        return sharedSecret;
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

    private short[][] sampleMatrix(byte[] r, int n1, int n2) {

        int i, j;
        short[][] R = new short[n1][n2];

        for (i = 0; i < n1; i++) {
            for (j = 0; j < n2; j++) {
                int sample = 0;
                int index = (i * n2 + j) * 2;
                R[i][j] = (short) sample(r[index] << 8 & 0xFF00 | r[index + 1] & 0xFF);

            }
        }
        return R;
    }

    private int sample(int r) {
        int s = 0;
        int t = r >>> 1; // Drop the least significant bit
        for (int k = 0; k < (params.CDF_TABLE.length - 1); k++) {
            if (t > params.CDF_TABLE[k])
                s++;
        }
        // Assuming that sign is either 0 or 1, flips sample if sign = 1
        if ((r & 1) != 0 && s != 0) {
            s = (short) (params.q - s + 1);
        }
        return s;
    }

    /** Encode a byte string to a m-by-n matrix **/
    private short[][] encode(byte[] m) {
        int i, j, k;
        short[][] out = new short[params.nbar][params.nbar];
        long temp, mask = (1 << params.B) - 1;

        for (i = 0; i < out.length; i++) {
            for (j = 0; j < out[i].length; j++) {

                temp = 0;
                for (k = 0; k < params.B; k++) {
                    int index = ((i * params.nbar + j) * params.B + k) / 8;
                    int shift = ((i * params.nbar + j) * params.B + k) & 7;
                    if ((m[index] & (0x80 >> shift)) != 0) { // litte-endian
                        temp |= 1 << k;
                    }
                }
                out[i][j] = (short) ( temp * (1 << (params.D-params.B)) & params.q);
            }
        }

        return out;
    }

    private byte[] decode(short[][] m) {
        byte[] out = new byte[params.bytesMU];

        int i, j, k;
        // uint8_t *pos = (uint8_t*)out;

        for (i = 0; i < m.length; i++) {
            for (j = 0; j < m[0].length; j++) {
                int b = 1 << params.B; 
                int d = 1 << (params.D-params.B);
                float temp = Math.round((float) m[i][j] / (float) d) & (b - 1);
                
                for (k = 0; k < params.B; k++) {
                    if (((int) (temp) & (1 << k)) != 0) {
                        int index = ((i * params.nbar + j) * params.B + k) / 8;
                        int shift = ((i * params.nbar + j) * params.B + k) & 7;
                        out[index] |= 0x80 >> shift;
                    }
                }
            }
        }
        return out;
    }

    public short[][] multiply(short[][] A, short[][] B) {
        short[][] out = new short[A.length][B[0].length];

        for (int i = 0; i < A.length; i++) {
            for (int j = 0; j < B[0].length; j++) {
                for (int k = 0; k < A[0].length; k++) {
                    out[i][j] = (short) ((A[i][k] * B[k][j] + out[i][j]) & params.q);
                }

            }
        }
        return out;
    }

    /**
     * Add matrices a and b (nbar x nbar)
     * 
     * @param a matrix A
     * @param b matrix B
     * @return C = A + B
     **/
    public short[][] add(short[][] a, short[][] b) {
        short[][] out = new short[a.length][a[0].length];
        for (int i = 0; i < a.length; i++) {
            for (int j = 0; j < a.length; j++) {
                out[i][j] = (short) ((a[i][j] + b[i][j]) & params.q);
            }
        }
        return out;
    }

    /**
     * Substract matrices a and b (nbar x nbar)
     * 
     * @param a matrix A
     * @param b matrix B
     * @return C = A - B
     **/
    public short[][] sub(short[][] A, short[][] B) {
        short[][] out = new short[params.nbar][params.nbar];
        for (int i = 0; i < params.nbar; i++) {
            for (int j = 0; j < params.nbar; j++) {
                if (A[i][j] >= B[i][j]) {
                    out[i][j] = (short) ((A[i][j] - B[i][j]) & params.q);
                } else {
                    out[i][j] = (short) ((params.q - B[i][j] + A[i][j] + 1) & params.q);
                }
            }
        }
        return out;
    }

    private short[][] genMatrixA(byte[] seedA) {
        short[][] A = new short[params.no][params.no];
        byte[] shakeA = new byte[params.no * 2];
        SHAKEDigest shake = new SHAKEDigest();
        // generate matrix A
        byte seedASeparated[] = new byte[2 + params.lenSeedA];
        System.arraycopy(seedA, 0, seedASeparated, 2, params.lenSeedA);
        for (int i = 0; i < params.no; i++) {
            seedASeparated[0] = (byte) (i >>> 8);
            seedASeparated[1] = (byte) (i);
            shake.update(seedASeparated, 0, seedASeparated.length);
            shake.doFinal(shakeA, 0, shakeA.length);
            for (int j = 0; j < params.no; j++) {
                A[i][j] = (short) ((shakeA[j * 2] << 8 & 0xFF00 | shakeA[j * 2 + 1] & 0xFF) & params.q);
            }
        }
        return A;
    }

    /**
     * Generate-and-multiply: generate matrix A (N x N) row-wise, multiply by s on the right.
     * Inputs: s, e (N x N_BAR) Output: out = A*s + e (N x N_BAR)
     **/
    private short[][] multiplyAddMatrices(short[][] A, short[][] B, short[][] E) {
        short[][] out = new short[A.length][B[0].length];

        // Matrix multiplication-addition A*s + e
        for (int i = 0; i < A.length; i++) {
            for (int j = 0; j < B[0].length; j++) {
                out[i][j] = E[i][j];
                for (int k = 0; k < A[0].length; k++) {
                    out[i][j] = (short) ((A[i][k] * B[k][j] + out[i][j]) & params.q);
                }
            }
        }
        return out;
    }

    private byte[] pack(short[][] input) {
        int i, j, k;

        int n1 = input.length;
        int n2 = input[0].length;
        byte[] out = new byte[(params.D * n1 * n2) / 8];

        for (i = 0; i < n1; i++) {
            for (j = 0; j < n2; j++) {
                for (k = 0; k < params.D; k++) {
                    if (((1 << params.D - 1 - k) & input[i][j]) != 0) {
                        int index = ((i * n2 + j) * params.D + k) / 8;
                        int shift = ((i * n2 + j) * params.D + k) & 7;
                        out[index] |= 0x80 >> shift;
                    }
                }
            }
        }
        return out;
    }

    private short[][] unpack(byte[] input, int n1, int n2) {
        short[][] out = new short[n1][n2];

        for (int i = 0; i < out.length; i++) {
            for (int j = 0; j < out[0].length; j++) {
                for (int k = 0; k < params.D; k++) {

                    int index = ((i * n2 + j) * params.D + k) / 8;
                    int shift = ((i * n2 + j) * params.D + k) & 7;
                    if ((input[index] & (0x80 >>> shift)) != 0)
                        out[i][j] |= 1 << (params.D - 1 - k);
                }
            }
        }
        return out;
    }

}
