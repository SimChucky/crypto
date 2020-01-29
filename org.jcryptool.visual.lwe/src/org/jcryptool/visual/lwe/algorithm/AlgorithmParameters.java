package org.jcryptool.visual.lwe.algorithm;

/**
 * This class holds a set of algorithm parameters as specified by FrodoKEM.
 * 
 * @author Daniel Hofmann
 *
 */
public class AlgorithmParameters {

<<<<<<< HEAD
    /** n ≡ 0 (mod 8) the main parameter **/
    public int no;
    /** a power-of-two integer modulus with exponent D ≤ 16 !! minus one for bit masking **/
    public int q; 
    public int D;
    public int stripeStep;
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

=======
    public int no;     // n ≡ 0 (mod 8) the main parameter
    public int q;      // a power-of-two integer modulus with exponent D ≤ 16 !! minus one for bit masking
    public int logQ;      // a power
    public int stripeStep, nbar;   // integer matrix dimensions with
    public int extractedBits;      // the number of bits encoded in each matrix entry
    public int l;      // B·m·n, the length of bit strings that are encoded as m-by-n matrices
    public int lenSeedA; // the byte length of seed used for pseudorandom pk-matrix generation
    public short[] CDF_TABLE;    // a probability distribution on Z, rounded Gaussian distribution
    public int bytesMU;
    public int cryptoBytes;
    public int secretKeyBytes;
    public int publicKeyBytes;
   
>>>>>>> refs/remotes/origin/lwe
}
