package ca.uqac.lif.artichoke;

import ca.uqac.lif.artichoke.crypto.AesEncryption;
import ca.uqac.lif.artichoke.crypto.EccEncryption;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Test;

import java.security.Security;

import static org.junit.Assert.*;

public class HistoryTest {

    private EccEncryption ecc;
    private byte[] groupKey;

    public HistoryTest() {
        groupKey = AesEncryption.generateNewKey().getEncoded();
        ecc = new EccEncryption();
    }

    @BeforeClass
    public static void init() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void testAdd() {
        Action action = new Action("first_name", "write", "Quentin");
        Peer peer = new Peer("Quentin", ecc.encodePublicKey());

        History history = new History();
        for(int i = 0; i < 100; i++)
            history.add(action, peer, "myGroup", groupKey, ecc);

        System.out.println(history);
    }

}