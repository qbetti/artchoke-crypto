package ca.uqac.lif.artichoke.crypto;

import ca.uqac.lif.artichoke.encoding.HexEncoder;
import ca.uqac.lif.artichoke.encoding.StringEncoder;

/**
 * Wrapper around parameters to use for or returned by {@link AesCtrEncryption} encryption/decryption methods
 */
public class AesCtrCipher {

    /**
     * The encrypted/decrypted data bytes
     */
    private byte[] dataBytes;

    /**
     * The IV used or to be used for encryption/decryption of the data
     */
    private byte[] iv;

    /**
     * Constructor by specifying the data to encrypt/decrypt or that
     * has just been encrypted/decrypted and the IV to use or that has just been used
     * @param dataBytes the data
     * @param iv the IV
     */
    public AesCtrCipher(byte[] dataBytes, byte[] iv) {
        this.dataBytes = dataBytes;
        this.iv = iv;
    }

    /**
     * Constructor by specifying the data to encrypt/decrypt or that
     * has just been encrypted/decrypted and the IV to use or that has just been used
     * @param dataBytes the data
     * @param hexIv the hexadecimal-encoded bytes of the IV
     */
    public AesCtrCipher(byte[] dataBytes, String hexIv) {
        this(dataBytes, HexEncoder.getInstance().decode(hexIv));
    }

    /**
     * Constructor by specifying the data to encrypt/decrypt or that
     * has just been encrypted/decrypted and the IV to use or that has just been used
     * @param hexData the hexadecimal-encoded bytes of the data
     * @param hexIv the hexadecimal-encoded bytes of the IV
     */
    public AesCtrCipher(String hexData, String hexIv) {
        this(HexEncoder.getInstance().decode(hexData), HexEncoder.getInstance().decode(hexIv));
    }

    /**
     * Encodes the data bytes
     * @param encoder the encoder to use
     * @return the encoded data bytes
     */
    public String encodeDataBytes(StringEncoder encoder) {
        return encoder.encodeToString(dataBytes);
    }

    /**
     * Encodes the data bytes in hexadecimal
     * @return the hex-encoded data bytes
     */
    public String encodeDataBytes() {
        return encodeDataBytes(HexEncoder.getInstance());
    }

    /**
     * Encodes the IV bytes
     * @param encoder the encoder to use
     * @return the encoded IV bytes
     */
    public String encodeIv(StringEncoder encoder) {
        return encoder.encodeToString(iv);
    }

    /**
     * Encodes the IV bytes in hexadecimal
     * @return the hex-encoded IV bytes
     */
    public String encodeIv() {
        return encodeIv(HexEncoder.getInstance());
    }

    /**
     * Returns the data bytes
     * @return the data bytes
     */
    public byte[] getDataBytes() {
        return dataBytes;
    }

    /**
     * Returns the IV
     * @return the IV
     */
    public byte[] getIv() {
        return iv;
    }
}
