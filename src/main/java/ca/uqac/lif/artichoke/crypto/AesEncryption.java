package ca.uqac.lif.artichoke.crypto;

import ca.uqac.lif.artichoke.encoding.HexEncoder;
import ca.uqac.lif.artichoke.encoding.StringEncoder;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;

public abstract class AesEncryption {

    /**
     * AES algorithm
     */
    public static final String AES = "AES";

    /**
     * Default AES secret key size in bits
     */
    public static final int DEFAULT_KEY_SIZE = 256; // in bits

    /**
     * The size of the AES keu for this instance
     */
    private int keySize;

    /**
     * The AES secret key used for this instance's encryption/decryption
     */
    private final SecretKey secretKey;


    /**
     * Constructor generating a new secret key
     * @param keySize the size in bits of the secret key to generate
     */
    public AesEncryption(int keySize) {
        this(generateNewKey(keySize));
        this.keySize = keySize;
    }

    /**
     * Constructor generating a new {@value DEFAULT_KEY_SIZE}-bit long secret key
     */
    public AesEncryption() {
        this(generateNewKey(DEFAULT_KEY_SIZE));
    }

    /**
     * Constructor by specifying the secret key used for
     * this instance's encryption/decryption
     * @param hexSecretKey the hexadecimal-encoded bytes of the secret key
     */
    public AesEncryption(String hexSecretKey) {
        this(hexSecretKey, HexEncoder.getInstance());
    }

    public AesEncryption(String encodedSecretKey, StringEncoder encoder) {
        this(encoder.decode(encodedSecretKey));
    }

    /**
     * Constructor by specifying the secret key used for
     * this instance's encryption/decryption
     * @param secretKey the secret key's bytes
     */
    public AesEncryption(byte[] secretKey) {
        this(toAESKey(secretKey));
    }

    /**
     * Constructor by specifying the secret key used for
     * this instance's encryption/decryption
     * @param secretKey the secret key
     */
    public AesEncryption(SecretKey secretKey) {
        this.secretKey = secretKey;
        this.keySize = secretKey.getEncoded().length;
    }


    /**
     * Converts a byte array to a proper {@link SecretKey} object.
     * @param secretKey the byte for the secret key (should respect the authorized sizes for AES)
     * @return the secret key
     */
    public static SecretKey toAESKey(byte[] secretKey) {
        return new SecretKeySpec(secretKey, AES);
    }

    /**
     * Generates a new secret key with the specified size
     * @param size the desired size of the generated secret key in bits
     * @return the generated secret key
     */
    public static SecretKey generateNewKey(int size) {
        try {
            KeyGenerator keyGen = KeyGenerator.getInstance(AES);
            keyGen.init(size);
            return keyGen.generateKey();
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Generates a new {@value #DEFAULT_KEY_SIZE}-bit long secret key
     * @return the generated secret key
     */
    public static SecretKey generateNewKey() {
        return generateNewKey(DEFAULT_KEY_SIZE);
    }

    /**
     * Encodes the secret key in hexadecimal
     * @return the hex-encoded bytes of the secret key
     */
    public String encodeSecretKey() {return encodeSecretKey(HexEncoder.getInstance());}

    /**
     * Encodes the secret key
     * @param encoder the encoder to use
     * @return the encoded bytes of the secret key
     */
    public String encodeSecretKey(StringEncoder encoder) {
        return encoder.encodeToString(secretKey.getEncoded());
    }

    public int getKeySize() {
        return keySize;
    }

    protected SecretKey getSecretKey() {
        return secretKey;
    }
}
