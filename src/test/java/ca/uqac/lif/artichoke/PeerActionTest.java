package ca.uqac.lif.artichoke;

import ca.uqac.lif.artichoke.crypto.AesEncryption;
import ca.uqac.lif.artichoke.encoding.HexEncoder;
import org.junit.Test;

import static org.junit.Assert.*;

public class PeerActionTest {

    @Test
    public void testEncode() {
        Action action = new Action("first_name", "write", "Quentin");
        EncryptedAction encryptedAction = EncryptedAction.encrypt(action, AesEncryption.generateNewKey().getEncoded());
        Peer peer = new Peer("Quentin", HexEncoder.getInstance().encodeToString("ThisIsAPublicKey"));

        PeerAction peerAction = new PeerAction(encryptedAction, peer, "myGroup", new Digest(new byte[0]));
        String encodedPeerAction = peerAction.encode();
        PeerAction decodedPeerAction = PeerAction.decode(encodedPeerAction);

        assertEquals(peerAction.toString(), decodedPeerAction.toString());
    }


}