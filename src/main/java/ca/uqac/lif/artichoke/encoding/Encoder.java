package ca.uqac.lif.artichoke.encoding;

public interface Encoder {

    public byte[] encode(byte[] bytes);
    public byte[] decode(byte[] encodedBytes);
}
