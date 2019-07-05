package ca.uqac.lif.artichoke;

import ca.uqac.lif.artichoke.crypto.AesEncryption;
import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class EncryptedActionTest {

    private byte[] groupKey;

    public EncryptedActionTest() {
        this.groupKey = AesEncryption.generateNewKey(256).getEncoded();
    }

    @Test
    public void testEncryption() {
        Action action = new Action("first_name", "write", "Quentin");
        EncryptedAction encryptedAction = EncryptedAction.encrypt(action, groupKey);
        Action decryptedAction = encryptedAction.decrypt(groupKey);
        assertEquals(action.toString(), decryptedAction.toString());
    }

    @Test
    public void testEncode() {
        Action action = new Action("first_name", "write", "Quentin");
        EncryptedAction encryptedAction = EncryptedAction.encrypt(action, groupKey);
        String encodedEncAction = encryptedAction.encode();
        EncryptedAction decodedEncAction = EncryptedAction.decode(encodedEncAction);
        assertEquals(encryptedAction.toString(), decodedEncAction.toString());
    }

}