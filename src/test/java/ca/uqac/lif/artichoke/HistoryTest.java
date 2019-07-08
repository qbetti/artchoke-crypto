package ca.uqac.lif.artichoke;

import ca.uqac.lif.artichoke.crypto.AesEncryption;
import ca.uqac.lif.artichoke.crypto.EccEncryption;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import java.security.Security;
import java.util.List;

import static org.junit.Assert.*;

public class HistoryTest {

    private EccEncryption ecc;
    private byte[] groupKey;
    private Peer peer;
    private History history;

    public static final Action BASIC_ACTION = new Action("first_name", "write", "Quentin");


    public HistoryTest() {
        groupKey = AesEncryption.generateNewKey().getEncoded();
        ecc = new EccEncryption();
        peer = new Peer("Quentin", ecc.encodePublicKey());
    }

    @BeforeClass
    public static void init() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Before
    public void initHistory() {
        history = new History();
        for(int i = 0; i < 100; i++)
            history.add(BASIC_ACTION, peer, "myGroup", groupKey, ecc.getPrivateKeyBytes());
    }

    @Test
    public void testAddVerify() {
        assertEquals(100, history.getSize());
        assertEquals(0, history.verify().size());

        EncryptedAction encryptedAction = EncryptedAction.encrypt(BASIC_ACTION, groupKey);
        Digest digest = Digest.sign(history.getLastDigest(), encryptedAction, "myGroup", ecc.getPrivateKeyBytes());

        PeerAction peerActionWithWrongGroup = new PeerAction(encryptedAction, peer, "wrongGroup", digest);
        history.add(peerActionWithWrongGroup);

        Peer peerWithWrongPK = new Peer("Moi", new EccEncryption().encodePublicKey());
        PeerAction peerActionWithWrongPeerPK = new PeerAction(encryptedAction, peerWithWrongPK, "myGroup", digest);
        history.add(peerActionWithWrongPeerPK);

        Action wrongAction = new Action("last_name", "write", "Betti");
        EncryptedAction encryptedWrongAction = EncryptedAction.encrypt(wrongAction, groupKey);
        PeerAction peerActionWithWrongAction = new PeerAction(encryptedWrongAction, peer, "myGroup", digest);
        history.add(peerActionWithWrongAction);

        List<DigestViolation> digestViolations = history.verify();
        assertEquals(3, digestViolations.size());

        assertEquals(100, digestViolations.get(0).getPosition());
        assertEquals(peerActionWithWrongGroup.toString(), digestViolations.get(0).getPeerAction().toString());

        assertEquals(101, digestViolations.get(1).getPosition());
        assertEquals(peerActionWithWrongPeerPK.toString(), digestViolations.get(1).getPeerAction().toString());

        assertEquals(102, digestViolations.get(2).getPosition());
        assertEquals(peerActionWithWrongAction.toString(), digestViolations.get(2).getPeerAction().toString());
    }

    @Test
    public void testEncode() {
        String encodedHistory = history.encode();
        History decodedHistory = History.decode(encodedHistory);
        assertEquals(history.toString(), decodedHistory.toString());
    }
}