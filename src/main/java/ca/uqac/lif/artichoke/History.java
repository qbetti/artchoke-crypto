package ca.uqac.lif.artichoke;

import ca.uqac.lif.artichoke.crypto.EccEncryption;
import com.google.gson.JsonArray;

import java.util.LinkedList;
import java.util.NoSuchElementException;

public class History {

    private LinkedList<PeerAction> peerActionSequence;


    public History() {
        this.peerActionSequence = new LinkedList<>();
    }


    public void add(Action action, Peer peer, String groupId, byte[] groupKey, EccEncryption ecc) {
        EncryptedAction encryptedAction = EncryptedAction.encrypt(action, groupKey);
        Digest digest = Digest.sign(getLastDigest(), encryptedAction, groupId, ecc);

        PeerAction peerAction = new PeerAction(encryptedAction, peer, groupId, digest);
        peerActionSequence.add(peerAction);
    }

    public JsonArray toJsonArray() {
        JsonArray array = new JsonArray();
        for(PeerAction peerAction: peerActionSequence) {
            array.add(peerAction.toJsonArray());
        }
        return array;
    }

    @Override
    public String toString() {
        return toJsonArray().toString();
    }

    private Digest getLastDigest() {
        try {
            return peerActionSequence.getLast().getDigest();
        } catch (NoSuchElementException e) {
            return null;
        }
    }
}
