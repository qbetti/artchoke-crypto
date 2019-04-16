package ca.uqac.lif.artichoke.encoding;

import org.apache.commons.codec.DecoderException;
import org.apache.commons.codec.binary.Hex;

public class HexEncoder extends StringEncoder {

    private static HexEncoder instance;

    private HexEncoder() {
    }

    @Override
    public String encodeToString(byte[] bytes) {
        return Hex.encodeHexString(bytes);
    }

    @Override
    public String decodeToString(String s) {
        return new String(decode(s));
    }

    @Override
    public String decodeToString(byte[] bytes) {
        return decodeToString(new String(bytes));
    }

    @Override
    public byte[] encode(byte[] bytes) {
        return Hex.encodeHexString(bytes).getBytes();
    }

    @Override
    public byte[] decode(byte[] encodedBytes) {
        return decode(new String(encodedBytes));
    }

    @Override
    public byte[] decode(String s) {
        try {
            return Hex.decodeHex(s);
        } catch (DecoderException e) {
            e.printStackTrace();
            return null;
        }
    }

    public static HexEncoder getInstance() {
        if (instance == null)
            instance = new HexEncoder();
        return instance;
    }
}
