package ca.uqac.lif.artichoke.crypto;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Test;
import static org.junit.Assert.*;

import javax.crypto.SecretKey;
import java.security.Security;
import java.util.Arrays;

public class AesEncryptionTest {

    @BeforeClass
    public static void init() {
        Security.addProvider(new BouncyCastleProvider());
    }

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
