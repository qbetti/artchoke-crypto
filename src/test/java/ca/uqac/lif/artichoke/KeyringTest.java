package ca.uqac.lif.artichoke;

import ca.uqac.lif.artichoke.crypto.AesCtrEncryption;
import ca.uqac.lif.artichoke.exceptions.*;
import com.google.gson.JsonObject;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Test;

import javax.crypto.SecretKey;
import java.io.File;
import java.io.IOException;
import java.security.Security;

import static org.junit.Assert.*;

public class KeyringTest {

    @BeforeClass
    public static void init() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testJson() throws PrivateKeyDecryptionException, GroupIdException, BadPassphraseException {
        String passphrase = "passphrase";
        Keyring keyRing = Keyring.generateNew(passphrase, true);

        SecretKey group0Key = AesCtrEncryption.generateNewKey();
        keyRing.addGroup("test", group0Key.getEncoded());

        SecretKey group1Key = AesCtrEncryption.generateNewKey();
        keyRing.addGroup( "test1", group1Key.getEncoded());

        JsonObject jKeyring = keyRing.toJson();

        Keyring o = Keyring.fromJson(jKeyring);
        JsonObject jO = o.toJson();

        assertEquals(jKeyring, jO);
    }

    @Test
    public void testGroupManagement() throws PrivateKeyDecryptionException, GroupIdException, BadPassphraseException {
        String passphrase = "passphrase";
        Keyring keyRing = Keyring.generateNew(passphrase, true);

        SecretKey group0Key = AesCtrEncryption.generateNewKey();
        // Test add group
        assertTrue(keyRing.addGroup( "group0", group0Key.getEncoded()));
        // Test retrieve group
        assertArrayEquals(group0Key.getEncoded(), keyRing.retrieveGroupKey(passphrase, "group0"));
    }

    @Test(expected = NonExistingGroupIdException.class)
    public void testRetrieveNonExistingGroup() throws PrivateKeyDecryptionException, GroupIdException, BadPassphraseException {
        String passphrase = "passphrase";
        Keyring keyRing = Keyring.generateNew(passphrase, true);
        keyRing.retrieveGroupKey( "group0");
    }

    @Test(expected = DuplicatedGroupIdException.class)
    public void testAddAlreadyExistingGroup() throws PrivateKeyDecryptionException, GroupIdException, BadPassphraseException {
        String passphrase = "passphrase";
        Keyring keyRing = Keyring.generateNew(passphrase, true);
        SecretKey group0Key = AesCtrEncryption.generateNewKey();
        keyRing.addGroup( "group0", group0Key.getEncoded());
        keyRing.addGroup("group0", group0Key.getEncoded());
    }

    @Test(expected = BadPassphraseException.class)
    public void testAddWithWrongPassphrase() throws PrivateKeyDecryptionException, GroupIdException, BadPassphraseException {
        String passphrase = "passphrase";
        String wrongPassphrase = "wrongPassphrase";

        Keyring keyRing = Keyring.generateNew(passphrase, false);
        SecretKey group0Key = AesCtrEncryption.generateNewKey();
        keyRing.addGroup( wrongPassphrase, "group0", group0Key.getEncoded());
    }

    @Test(expected = BadPassphraseException.class)
    public void testRetrieveWithWrongPassphrase() throws PrivateKeyDecryptionException, GroupIdException, BadPassphraseException {
        String passphrase = "passphrase";
        String wrongPassphrase = "wrongPassphrase";
        Keyring keyRing = Keyring.generateNew(passphrase, true);

        SecretKey group0Key = AesCtrEncryption.generateNewKey();
        keyRing.addGroup( "group0", group0Key.getEncoded());
        keyRing.retrieveGroupKey(wrongPassphrase, "group0");
    }

    @Test
    public void testStayLocked() throws PrivateKeyDecryptionException, GroupIdException, BadPassphraseException {
        String passphrase = "passphrase";
        Keyring keyRing = Keyring.generateNew(passphrase, false);

        SecretKey group0Key = AesCtrEncryption.generateNewKey();

        assertTrue(keyRing.addGroup(passphrase, "group0", group0Key.getEncoded()));
        assertArrayEquals(group0Key.getEncoded(), keyRing.retrieveGroupKey(passphrase, "group0"));
    }

    @Test
    public void testStayUnlocked() throws PrivateKeyDecryptionException, GroupIdException, BadPassphraseException {
        String passphrase = "passphrase";
        Keyring keyRing = Keyring.generateNew(passphrase, true);

        SecretKey group0Key = AesCtrEncryption.generateNewKey();

        assertTrue(keyRing.addGroup( "group0", group0Key.getEncoded()));
        assertArrayEquals(group0Key.getEncoded(), keyRing.retrieveGroupKey("group0"));
    }

    @Test
    public void testSaveLoad() throws PrivateKeyDecryptionException, GroupIdException, BadPassphraseException, IOException {
        String passphrase = "passphrase";
        Keyring keyRing = Keyring.generateNew(passphrase, true);

        SecretKey group0Key = AesCtrEncryption.generateNewKey();
        keyRing.addGroup("test", group0Key.getEncoded());

        SecretKey group1Key = AesCtrEncryption.generateNewKey();
        keyRing.addGroup( "test1", group1Key.getEncoded());

        keyRing.saveToFile(new File("keyring.json"));

        Keyring o = Keyring.loadFromFile(new File("keyring.json"));
        assertEquals(keyRing.toJson(), o.toJson());
    }

    @Test
    public void testVerifyPassphrase() throws PrivateKeyDecryptionException {
        String passphrase = "passphrase";
        String wrongPassphrase = "wrongPassphrase";

        Keyring keyRing = Keyring.generateNew(passphrase, true);
        assertTrue(keyRing.verifyPassphrase());
        assertTrue(keyRing.verifyPassphrase(passphrase));
        assertFalse(keyRing.verifyPassphrase(wrongPassphrase));

        keyRing = Keyring.generateNew(passphrase, false);
        assertFalse(keyRing.verifyPassphrase());
        assertTrue(keyRing.verifyPassphrase(passphrase));
        assertFalse(keyRing.verifyPassphrase(wrongPassphrase));
    }

    @Test
    public void testVerifySignature() throws PrivateKeyDecryptionException, BadPassphraseException {
        Keyring kr = Keyring.generateNew("root", true);
        String data = "data";

        byte[] signature = kr.sign(data.getBytes(), null);

        assertTrue(kr.verifySignature(signature, data.getBytes()));
        assertTrue(Keyring.verifySignature(signature, data.getBytes(), kr.getHexPublicKey()));
    }
}