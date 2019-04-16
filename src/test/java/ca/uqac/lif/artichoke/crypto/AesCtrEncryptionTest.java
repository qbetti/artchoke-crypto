package ca.uqac.lif.artichoke.crypto;

import ca.uqac.lif.artichoke.encoding.Base64Encoder;
import ca.uqac.lif.artichoke.encoding.StringEncoder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.crypto.SecretKey;

import java.security.Security;

import static org.junit.Assert.*;

public class AesCtrEncryptionTest {

    private final static byte[] DATA = "This is dummy data".getBytes();

    private AesCtrEncryption aes;
    private AesCtrCipher defaultEncryptedCipher;

    @BeforeClass
    public static void init () {
        Security.addProvider(new BouncyCastleProvider());
    }

    public AesCtrEncryptionTest() {
        aes = new AesCtrEncryption();
        defaultEncryptedCipher = aes.encrypt(DATA);
    }

    @Test
    public void testEncryptionDecryption() {
        AesCtrCipher encryptedCipher0 = aes.encrypt(DATA);
        assertNotNull(encryptedCipher0.getDataBytes());
        assertNotEquals(0, encryptedCipher0.getDataBytes().length);
        assertEquals(AesCtrEncryption.DEFAULT_IV_SIZE, encryptedCipher0.getIv().length);

        AesCtrCipher decryptedCipher0 = aes.decrypt(encryptedCipher0.getDataBytes(), encryptedCipher0.getIv());
        assertArrayEquals(DATA, decryptedCipher0.getDataBytes());

        decryptedCipher0 = aes.decrypt(encryptedCipher0);
        assertArrayEquals(DATA, decryptedCipher0.getDataBytes());

        decryptedCipher0 = aes.decrypt(encryptedCipher0.encodeDataBytes(), encryptedCipher0.encodeIv());
        assertArrayEquals(DATA, decryptedCipher0.getDataBytes());

        StringEncoder b64 = Base64Encoder.getInstance();
        decryptedCipher0 = aes.encrypt(b64.decode(encryptedCipher0.encodeDataBytes(b64)), b64.decode(encryptedCipher0.encodeIv(b64)));
        assertArrayEquals(DATA, decryptedCipher0.getDataBytes());

    }

}
