package ca.uqac.lif.artichoke.crypto;


import ca.uqac.lif.artichoke.encoding.HexEncoder;

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
    private static final int PARALLELISATION_PARAM = 1;
    private static final int BLOCK_SIZE = 8;
    private static final int N = 262144;

    /**
     * Desired size in bytes of the derived key
     */
    private static final int DERIVED_KEY_SIZE = 32; // in bytes

    /**
     * Default size in bytes of the generated salts
     */
    private static final int DEFAULT_SCRYPT_SALT_SIZE = 32; // in bytes

    /**
     * The salt to use for this instance's derivations
     */
    private byte[] salt;

    /**
     * Constructor by specifying the salt bytes that will be used for the scrypt
     * key derivation function.
     * @param salt the salt bytes. If null, will generate a random
     *             {@value #DEFAULT_SCRYPT_SALT_SIZE}-byte salt
     */
    public Scrypt(byte[] salt) {
        if (salt == null) {
            salt = generateNewSalt();
        }
        this.salt = salt;
    }

    /**
     * Generates a random {@value #DEFAULT_SCRYPT_SALT_SIZE}-byte long salt
     * @return the generated salt
     */
    public static byte[] generateNewSalt() {
        SecureRandom random = new SecureRandom();
        byte[] salt = new byte[DEFAULT_SCRYPT_SALT_SIZE];
        random.nextBytes(salt);
        return salt;
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
     * Constructor that generates a random {@value #DEFAULT_SCRYPT_SALT_SIZE}-byte salt
     */
    public Scrypt() {
        this((byte[]) null);
    }

    /**
     * Generates a 256-bit key derived from the specified passphrase using the scrypt
     * derivation function
     * @param passphrase the passphrase bytes
     * @return the derived key
     */
    public byte[] deriveKey(byte[] passphrase) {
        return org.bouncycastle.crypto.generators.SCrypt.generate(passphrase, salt, N, BLOCK_SIZE, PARALLELISATION_PARAM, DERIVED_KEY_SIZE);
    }

    /**
     * Generates a 256-bit key derived from the specified passphrase using the scrypt
     * derivation function
     * @param passphrase the passphrase
     * @return the derived key
     */
    public byte[] deriveKey(String passphrase) {
        return deriveKey(passphrase.getBytes());
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
