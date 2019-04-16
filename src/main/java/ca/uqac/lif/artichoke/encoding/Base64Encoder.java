package ca.uqac.lif.artichoke.encoding;

import java.util.Base64;

public class Base64Encoder extends StringEncoder {

    private static Base64Encoder instance;

    private Base64Encoder(){}

    @Override
    public String encodeToString(byte[] bytes) {
        return Base64.getEncoder().encodeToString(bytes);
    }

    @Override
    public String decodeToString(byte[] bytes) {
        return new String(Base64.getDecoder().decode(bytes));
    }

    @Override
    public byte[] encode(byte[] bytes) {
        return Base64.getEncoder().encode(bytes);
    }

    @Override
    public byte[] decode(byte[] encodedBytes) {
        return Base64.getDecoder().decode(encodedBytes);
    }

    public static Base64Encoder getInstance() {
        if(instance == null)
            instance = new Base64Encoder();
        return instance;
    }
}
