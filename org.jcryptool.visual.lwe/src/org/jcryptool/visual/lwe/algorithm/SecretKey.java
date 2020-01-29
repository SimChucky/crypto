package org.jcryptool.visual.lwe.algorithm;

public class SecretKey {

    private byte[] s;
    private byte[] pk;
    private short[][] matrixS;
    private byte[] pkHash;
    
    public SecretKey(byte[] s, short[][] matrixS, byte[] pk, byte[] pkHash) {
        super();
        this.s = s;
        this.pk = pk;
        this.matrixS = matrixS;
        this.pkHash = pkHash;
    }

    public SecretKey() {
    }

    public byte[] getS() {
        return s;
    }

    public void setS(byte[] s) {
        this.s = s;
    }

    public byte[] getPk() {
        return pk;
    }

    public void setPk(byte[] pk) {
        this.pk = pk;
    }

    public short[][] getMatrixS() {
        return matrixS;
    }

    public byte[] getPkHash() {
        return pkHash;
    }

    public void setPkHash(byte[] pkHash) {
        this.pkHash = pkHash;
    }

    public void setMatrixS(short[][] matrixS) {
        this.matrixS = matrixS;
    }
    
    
}
