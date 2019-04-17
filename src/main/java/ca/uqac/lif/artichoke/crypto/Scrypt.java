package ca.uqac.lif.artichoke.crypto;


import ca.uqac.lif.artichoke.encoding.HexEncoder;
import org.bouncycastle.crypto.generators.SCrypt;

import java.security.SecureRandom;

/**
 * Provides a wrapper around {@link org.bouncycastle.crypto.generators.SCrypt} class
 * for scrypt key derivation function and methods to combine it with AES encryption.
 */
public class Scrypt {

    /**
     * Scrypt derivation function parameters to use
     * TODO: more explanation
     */
    private static final int P = 1;
    private static final int R = 8;
    private static final int N = 16384;

    /**
     * Desired size in bytes of the derived key
     */
    public static final int DEFAULT_DERIVED_KEY_SIZE = 32; // in bytes

    /**
     * Default size in bytes of the generated salts
     */
    public static final int DEFAULT_SCRYPT_SALT_SIZE = 32; // in bytes

    /**
     * The salt to use for this instance's derivations
     */
    private byte[] salt;

    /**
     * Constructor that generates a random byte salt of specified size
     * @param saltSize the length of the salt to generate in bytes
     */
    public Scrypt(int saltSize) {
        this(generateNewSalt(saltSize));
    }

    /**
     * Constructor that generates a random {@value #DEFAULT_SCRYPT_SALT_SIZE}-byte salt
     */
    public Scrypt() {
        this(DEFAULT_SCRYPT_SALT_SIZE);
    }

    /**
     * Constructor by specifying the salt bytes that will be used for the scrypt
     * key derivation function.
     * @param salt the salt bytes.
     */
    public Scrypt(byte[] salt) {
        this.salt = salt;
    }

    /**
     * Constructor by specifying the salt hexadecimal representation that will be used
     * for the scrypt key derivation function
     * @param hexSalt the hexadecimal representation of the salt
     */
    public Scrypt(String hexSalt) {
        this(HexEncoder.getInstance().decode(hexSalt));
    }

    /**
     * Generates a random salt of specified length
     * @param size the length of the salt in bytes
     * @return the generated salt
     */
    public static byte[] generateNewSalt(int size) {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[size];
        random.nextBytes(salt);
        return salt;
    }

    /**
     * Generates a random {@value #DEFAULT_SCRYPT_SALT_SIZE}-byte long salt
     * @return the generated salt
     */
    public static byte[] generateNewSalt() {
        return generateNewSalt(DEFAULT_SCRYPT_SALT_SIZE);
    }

    /**
     * Generates a key of specified length derived from the specified passphrase using the scrypt
     * derivation function
     * @param passphrase the passphrase bytes
     * @param keySize the desired key size in bytes
     * @return the derived key
     */
    public byte[] deriveKey(byte[] passphrase, int keySize) {
        return SCrypt.generate(passphrase, salt, N, R, P, keySize);
    }

    /**
     * Generates a {@value DEFAULT_DERIVED_KEY_SIZE}-byte key derived from the specified passphrase using the scrypt
     * derivation function
     * @param passphrase the passphrase bytes
     * @return the derived key
     */
    public byte[] deriveKey(byte[] passphrase) {
        return deriveKey(passphrase, DEFAULT_DERIVED_KEY_SIZE);
    }

    /**
     * Generates a {@value DEFAULT_DERIVED_KEY_SIZE}-byte key derived from the specified passphrase using the scrypt
     * derivation function
     * @param passphrase the passphrase
     * @return the derived key
     */
    public byte[] deriveKey(String passphrase) {
        return deriveKey(passphrase.getBytes());
    }

    /**
     * Generates a key of specified length derived from the specified passphrase using the scrypt
     * derivation function
     * @param passphrase the passphrase
     * @param keySize the desired key size in bytes
     * @return the derived key
     */
    public byte[] deriveKey(String passphrase, int keySize) {
        return deriveKey(passphrase.getBytes(), keySize);
    }

    /**
     * Returns the salt used for this scrypt instance
     * @return the salt used for this scrypt instance
     */
    public byte[] getSalt() {
        return salt;
    }

    /**
     * Encodes the salt in hexadecimal
     * @return the hexadecimal representation of the salt
     */
    public String encodeSalt() {
        return HexEncoder.getInstance().encodeToString(salt);
    }
}
