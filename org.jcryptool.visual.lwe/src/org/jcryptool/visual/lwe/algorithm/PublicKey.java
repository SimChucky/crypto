package org.jcryptool.visual.lwe.algorithm;

public class PublicKey {
    private byte[] seedA;
    private byte[] matrixB;

    public PublicKey(byte[] seedA, byte[] pk_b) {
        this.seedA = seedA;
        this.matrixB = pk_b;
    }

    public byte[] getSeedA() {
        return seedA;
    }

    public void setSeedA(byte[] seedA) {
        this.seedA = seedA;
    }

    public byte[] getMatrixB() {
        return matrixB;
    }

    public void setMatrixB(byte[] matrixB) {
        this.matrixB = matrixB;
    }

}
