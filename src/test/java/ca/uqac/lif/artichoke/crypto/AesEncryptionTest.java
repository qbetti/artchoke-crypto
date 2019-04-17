package ca.uqac.lif.artichoke.crypto;

import org.junit.Test;

import javax.crypto.SecretKey;
import java.util.Arrays;

import static org.junit.Assert.*;

public class AesEncryptionTest {

    @Test
    public void testGenerateKey() {
        SecretKey secretKey = AesEncryption.generateNewKey();
        assertNotNull(secretKey);
        assertEquals(AesEncryption.DEFAULT_KEY_SIZE, secretKey.getEncoded().length * 8);

        SecretKey oSecretKey = AesEncryption.generateNewKey();
        assertFalse(Arrays.equals(secretKey.getEncoded(), oSecretKey.getEncoded()));

        SecretKey littleKey = AesEncryption.generateNewKey(128);
        assertNotNull(littleKey);
        assertEquals(128, littleKey.getEncoded().length * 8);
    }
}
