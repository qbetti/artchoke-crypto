package ca.uqac.lif.artichoke;

import ca.uqac.lif.artichoke.encoding.HexEncoder;
import org.junit.Test;

import static org.junit.Assert.*;

public class PeerTest {

    @Test
    public void testEncode() {


        Peer peer = new Peer("Quentin", HexEncoder.getInstance().encodeToString("ThisIsAPublicKey"));
        String encodedPeer = peer.encode();
        System.out.println(encodedPeer);
        Peer decodedPeer = Peer.decode(encodedPeer);

        assertEquals(peer.toString(), decodedPeer.toString());
    }

}