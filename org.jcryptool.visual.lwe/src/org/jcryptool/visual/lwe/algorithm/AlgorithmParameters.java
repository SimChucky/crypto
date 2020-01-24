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
    public int logQ;
    public int stripeStep;
    public int nbar;
    /** the number of bits encoded in each matrix entry **/
    public int extractedBits;
    /** the byte length of seed used for pseudorandom pk-matrix generation **/
    public int lenSeedA; 
    /** a probability distribution on Z, rounded Gaussian distribution **/
    public short[] CDF_TABLE; 
    public int bytesMU;
    /** crypto bytes = size of pkHash **/
    public int cryptoBytes;
    /** sizeof(seed_A) + (loqQ * N * nbar)/8 **/
    public int publicKeyBytes;
    /** sizeof(s) + publicKeyBytes + 2 * N * NBAR + cryptoBytes **/
    public int secretKeyBytes;
    /** (logQ * N * nbar)/8 + (loqQ * nbar * nbar)/8 **/
    public int cypherTextBytes;

}
