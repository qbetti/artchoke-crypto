package ca.uqac.lif.artichoke.crypto;


import ca.uqac.lif.artichoke.encoding.HexEncoder;
import ca.uqac.lif.artichoke.encoding.StringEncoder;

/**
 * Wrapper around an elliptic curve signature
 */
public class EccSignature {

    /**
     * The signature bytes
     */
    private byte[] bytes;

    /**
     * Constructor by specifying the signature
     * @param bytes the signature
     */
    public EccSignature(byte[] bytes) {
        this.bytes = bytes;
    }

    /**
     * Returns the signature bytes
     * @return the signature bytes
     */
    public byte[] getBytes() {
        return bytes;
    }

    /**
     * Performs the hexadecimal-encoding of the signature bytes
     * @return the hexadecimal-encoded bytes of the signature
     */
    public String encode() {
        return encode(HexEncoder.getInstance());
    }

    public String encode(StringEncoder encoder) {
        return encoder.encodeToString(bytes);
    }
}
