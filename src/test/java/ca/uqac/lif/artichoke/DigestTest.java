package ca.uqac.lif.artichoke;

import ca.uqac.lif.artichoke.crypto.AesEncryption;
import ca.uqac.lif.artichoke.crypto.EccEncryption;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Test;

import java.security.Security;

import static org.junit.Assert.*;

public class DigestTest {

    private EccEncryption ecc;
    private byte[] groupKey;

    public DigestTest() {
        groupKey = AesEncryption.generateNewKey().getEncoded();
        ecc = new EccEncryption();
    }

    @BeforeClass
    public static void init() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testSign() {
        Action action = new Action("first_name", "write", "Quentin");
        EncryptedAction encryptedAction = EncryptedAction.encrypt(action, groupKey);

        Digest digest = Digest.sign(null, encryptedAction, "myGroup", ecc.getPrivateKeyBytes());
        String encodedDigest = digest.encode();
        Digest decodedDigest = Digest.decode(encodedDigest);
        assertTrue(decodedDigest.verify(null, encryptedAction, "myGroup", ecc.getPublicKeyBytes()));
    }

}