package ca.uqac.lif.artichoke.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Test;

import java.security.Security;
import java.util.Arrays;

import static org.junit.Assert.*;

public class ScryptTest {

    private static final String PASSPHRASE = "passphrase";
    private static final String WRONG_PASSPHRASE = "wrong passphrase";
    private Scrypt scrypt;

    @BeforeClass
    public static void init () {
        Security.addProvider(new BouncyCastleProvider());
    }

    public ScryptTest() {
        scrypt = new Scrypt();
    }

    @Test
    public void testGenerateSalt() {
        byte[] salt = Scrypt.generateNewSalt();
        assertNotNull(salt);
        assertEquals(Scrypt.DEFAULT_SCRYPT_SALT_SIZE, salt.length);

        byte[] otherSalt = Scrypt.generateNewSalt();
        assertFalse(Arrays.equals(salt, otherSalt));

        salt = Scrypt.generateNewSalt(16);
        assertEquals(16, salt.length);
    }

    @Test
    public void testDeriveKey() {
        byte[] key0 = scrypt.deriveKey(PASSPHRASE);
        assertNotNull(key0);
        assertEquals(key0.length, Scrypt.DEFAULT_DERIVED_KEY_SIZE);

        Scrypt sc = new Scrypt(scrypt.getSalt());
        byte[] key1 = sc.deriveKey(PASSPHRASE);
        assertArrayEquals(key0, key1);

        sc = new Scrypt(scrypt.encodeSalt());
        key1 = sc.deriveKey(PASSPHRASE);
        assertArrayEquals(key0, key1);

        key1 = scrypt.deriveKey(WRONG_PASSPHRASE);
        assertFalse(Arrays.equals(key0, key1));

        sc = new Scrypt(16);
        key1 = sc.deriveKey(PASSPHRASE);
        assertEquals(16, sc.getSalt().length);
        assertFalse(Arrays.equals(key0, key1));

        sc = new Scrypt();
        key1 = sc.deriveKey(PASSPHRASE, 16);
        assertEquals(16, key1.length);
    }
}
