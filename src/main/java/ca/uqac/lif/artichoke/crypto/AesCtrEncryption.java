package ca.uqac.lif.artichoke.crypto;


import ca.uqac.lif.artichoke.encoding.StringEncoder;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import java.security.*;

/**
 * Provides a wrapper around AES encryption/decryption from BouncyCastle and secret key generation.
 * The full AES algorithm used is {@value #AES_COUNTER_MODE}, which is the AES algorithm
 * with Counter Mode (no padding).
 */
public class AesCtrEncryption extends AesEncryption {

    /**
     * AES algorithm with Counter mode and no padding
     */
    public static final String AES_COUNTER_MODE = "AES/CTR/NoPadding";

    /**
     * Default size in bytes for generated IVs
     */
    public static final int DEFAULT_IV_SIZE = 16; // in bytes


    public AesCtrEncryption() {
        super();
    }

    public AesCtrEncryption(int keySize) {
        super(keySize);
    }

    public AesCtrEncryption(String hexSecretKey) {
        super(hexSecretKey);
    }

    public AesCtrEncryption(String encodedSecretKey, StringEncoder encoder) {
        super(encodedSecretKey, encoder);
    }

    public AesCtrEncryption(byte[] secretKey) {
        super(secretKey);
    }

    public AesCtrEncryption(SecretKey secretKey) {
        super(secretKey);
    }

    /**
     * Generates a new random IV with the specified size
     * @param size the desired size of the generated IV in bytes
     * @return the generated IV
     */
    public static byte[] generateIv(int size) {
        byte[] iv = new byte[size];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);
        return iv;
    }

    /**
     * Encrypts data using {@value #AES_COUNTER_MODE} algorithm and a specified IV
     * @param data the data to encrypt
     * @param iv the IV used for the encryption
     * @return the cipher containing the encrypted data and the IV used for encryption
     */
    public AesCtrCipher encrypt(byte[] data, byte[] iv) {
        byte[] encryptedData = doCipher(Cipher.ENCRYPT_MODE, iv, data);
        if(encryptedData == null)
            return null;

        return new AesCtrCipher(encryptedData, iv);
    }

    /**
     * Encrypts data using {@value #AES_COUNTER_MODE} algorithm and a random IV of specified size
     * @param data the data to encrypt
     * @param ivSize the size of the IV to generate for this encryption
     * @return the cipher containing the encrypted data and the IV used for encryption
     */
    public AesCtrCipher encrypt(byte[] data, int ivSize) {
        return encrypt(data, generateIv(ivSize));
    }

    /**
     * Encrypts data using {@value #AES_COUNTER_MODE} algorithm and a random IV
     * @param data the data to encrypt
     * @return the cipher containing the encrypted data and the IV used for encryption
     */
    public AesCtrCipher encrypt(byte[] data) {
        return encrypt(data, generateIv(DEFAULT_IV_SIZE));
    }

    /**
     * Encrypts the data of a {@link AesCtrCipher} using {@value #AES_COUNTER_MODE} algorithm
     * and the contained IV
     * @param cipher the cipher containing the data to encrypt and the IV to use
     * @return the cipher containing the encrypted data and the IV used for encryption
     */
    public AesCtrCipher encrypt(AesCtrCipher cipher) {
        return encrypt(cipher.getDataBytes(), cipher.getIv());
    }

    /**
     * Encrypts data using {@value #AES_COUNTER_MODE} algorithm and a specified IV
     * @param hexData the hexadecimal-encoded bytes of the data to encrypt
     * @param hexIv the hexadecimal-encoded bytes of the IV
     * @return the cipher containing the encrypted data and the IV used for encryption
     */
    public AesCtrCipher encrypt(String hexData, String hexIv) {
        return encrypt(new AesCtrCipher(hexData, hexIv));
    }

    /**
     * Decrypts data using {@value #AES_COUNTER_MODE} algorithm and the corresponding IV
     * @param encryptedData the data to decrypt
     * @param iv the IV to use for decryption
     * @return the cipher containing the decrypted data and the IV used for decryption,
     *          or null if data is null
     */
    public AesCtrCipher decrypt(byte[] encryptedData, byte[] iv) {
        byte[] data = doCipher(Cipher.DECRYPT_MODE, iv, encryptedData);
        if(data == null)
            return null;

        return new AesCtrCipher(data, iv);
    }

    /**
     * Decrypts the data of a {@link AesCtrCipher} using {@value #AES_COUNTER_MODE} algorithm
     * and the contained IV
     * @param encryptedCipher the cipher containing the data to encrypt and the IV to use
     * @return the cipher containing the decrypted data and the IV used for decryption
     */
    public AesCtrCipher decrypt(AesCtrCipher encryptedCipher) {
        return decrypt(encryptedCipher.getDataBytes(), encryptedCipher.getIv());
    }

    /**
     * Decrypts data using {@value #AES_COUNTER_MODE} algorithm and the corresponding IV
     * @param hexEncryptedData the hexadecimal-encoded bytes of the data to decrypt
     * @param hexIv the hexadecimal-encoded bytes of the IV to use for decryption
     * @return the cipher containing the decrypted data and the IV used for decryption
     */
    public AesCtrCipher decrypt(String hexEncryptedData, String hexIv) {
        return decrypt(new AesCtrCipher(hexEncryptedData, hexIv));
    }

    /**
     * Performs {@value #AES_COUNTER_MODE} encryption or decryption of the
     * specified data with a specified IV
     * @param cipherMode cipher mode (encryption or decryption)
     * @param iv the IV to use for encryption/decryption
     * @param data the data to encrypt/decrypt
     * @return the encrypted/decrypted data, or null if something goes wrong
     */
    private byte[] doCipher(int cipherMode, byte[] iv, byte[] data) {
        if(iv == null)
            return null;

        Cipher cipher = null;
        try {
            cipher = Cipher.getInstance(AES_COUNTER_MODE);
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
            e.printStackTrace();
            return null;
        }

        try {
            cipher.init(cipherMode, getSecretKey(), new IvParameterSpec(iv));
        } catch (InvalidKeyException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            return null;
        }

        try {
            return cipher.doFinal(data);
        } catch (IllegalBlockSizeException | BadPaddingException e) {
            e.printStackTrace();
            return null;
        }
    }
}
