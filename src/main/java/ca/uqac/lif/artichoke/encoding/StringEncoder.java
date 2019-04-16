package ca.uqac.lif.artichoke.encoding;

public abstract class StringEncoder implements Encoder {

    public abstract String encodeToString(byte[] bytes);
    public abstract String decodeToString(byte[] bytes);

    public byte[] decode(String s) {
        return decode(s.getBytes());
    }

    public byte[] encode(String s) {
        return encode(s.getBytes());
    }

    public String encodeToString(String s) {
        return encodeToString(s.getBytes());
    }

    public String decodeToString(String s) {
        return decodeToString(s.getBytes());
    }

}
