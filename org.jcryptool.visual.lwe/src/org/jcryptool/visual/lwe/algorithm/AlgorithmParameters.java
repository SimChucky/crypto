package org.jcryptool.visual.lwe.algorithm;

/**
 * This class holds a set of algorithm parameters as specified by FrodoKEM.
 * 
 * @author Daniel Hofmann
 *
 */
public class AlgorithmParameters {

    /** n ≡ 0 (mod 8) the main parameter **/
    public int no;
    /** a power-of-two integer modulus with exponent D ≤ 16 !! minus one for bit masking **/
    public int q; 
    public int D;
    public int nbar;
    /** the number of bits encoded in each matrix entry **/
    public int B;
    /** the byte length of seed used for pseudorandom pk-matrix generation **/
    public int lenSeedA; 
    /** a probability distribution on Z, rounded Gaussian distribution **/
    public int[] CDF_TABLE; 
    public int bytesMU;
    /** crypto bytes = size of pkHash **/
    public int cryptoBytes;
    /** sizeof(seed_A) + (loqQ * N * nbar)/8 **/
    public int publicKeyBytes;
    /** sizeof(s) + publicKeyBytes + 2 * N * NBAR + cryptoBytes **/
    public int secretKeyBytes;
    /** (logQ * N * nbar)/8 + (loqQ * nbar * nbar)/8 **/
    public int cypherTextBytes;
    public int lenX;
    
    
    public static AlgorithmParameters frodo640() {
        AlgorithmParameters params = new AlgorithmParameters();
        params.no = 640;
        params.D = 15;
        params.q = 0x7fff;
        params.B = 2;
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
        return params;
    }
    
    public static AlgorithmParameters frodo976() {

        AlgorithmParameters params = new AlgorithmParameters();
        params.no = 976;
        params.q = 0xffff;
        params.D = 16;
        params.B = 3;
        params.nbar = 8;
        params.lenSeedA = 16;
        params.cryptoBytes = 24;
        params.lenX = 2;
        params.CDF_TABLE =new int[]{5638, 15915, 23689, 28571, 31116, 32217, 32613, 32731, 32760, 32766, 32767};
        params.bytesMU = (params.B * params.nbar * params.nbar) / 8;
        params.secretKeyBytes = 31296;
        params.publicKeyBytes = 15632; 
        params.cypherTextBytes = 15744;
        return params;
    }
    // Frodo1344 returns Parameters struct no.1344
    public static AlgorithmParameters frodo1344() {

        AlgorithmParameters params = new AlgorithmParameters();

        params.no = 1344;
        params.q = 0xffff;
        params.D = 16;
        params.B = 4;
        params.nbar = 8;
        params.lenSeedA = 16;
        params.cryptoBytes = 32;
        params.lenX = 2;
        params.CDF_TABLE = new int[]{9142, 23462, 30338, 32361, 32725, 32765, 32767};
        params.bytesMU = (params.B * params.nbar * params.nbar) / 8;
        params.secretKeyBytes = 43088;
        params.publicKeyBytes = 21520; 
        params.cypherTextBytes = 21632;
        return params;
    }
}
