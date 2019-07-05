package ca.uqac.lif.artichoke;

import ca.uqac.lif.artichoke.crypto.EccEncryption;
import ca.uqac.lif.artichoke.encoding.Base64Encoder;
import ca.uqac.lif.artichoke.encoding.HexEncoder;
import ca.uqac.lif.artichoke.exceptions.BadPassphraseException;
import ca.uqac.lif.artichoke.exceptions.GroupIdException;
import ca.uqac.lif.artichoke.exceptions.PrivateKeyDecryptionException;
import ca.uqac.lif.artichoke.keyring.Keyring;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;
import com.sun.org.apache.xerces.internal.util.HTTPInputSource;

import java.util.*;
import java.util.logging.Logger;

public class History {

    private final static Logger logger = Logger.getLogger(History.class.getName());

    private final static Base64Encoder BASE64_ENCODER = Base64Encoder.getInstance();
    private final static HexEncoder HEX_ENCODER = HexEncoder.getInstance();

    private LinkedList<PeerAction> peerActionSequence;


    public History() {
        this.peerActionSequence = new LinkedList<>();
    }


    public void add(Action action, Peer peer, String groupId, byte[] groupKey, Keyring kr) {
        EncryptedAction encryptedAction = EncryptedAction.encrypt(action, groupKey);
        Digest digest = Digest.sign(getLastDigest(), encryptedAction, groupId, kr);

        PeerAction peerAction = new PeerAction(encryptedAction, peer, groupId, digest);
        peerActionSequence.add(peerAction);
    }

    public void add(Action action, Peer peer, String groupId, Keyring kr) {
        try {
            EncryptedAction encryptedAction = EncryptedAction.encrypt(action, kr.retrieveGroupKey(groupId));
            Digest digest = Digest.sign(getLastDigest(), encryptedAction, groupId, kr);

            PeerAction peerAction = new PeerAction(encryptedAction, peer, groupId, digest);
            peerActionSequence.add(peerAction);

        } catch (GroupIdException | PrivateKeyDecryptionException | BadPassphraseException e) {
            e.printStackTrace();
        }
    }

    public void add(Action action, Peer peer, String groupId, byte[] groupKey, EccEncryption ecc) {
        EncryptedAction encryptedAction = EncryptedAction.encrypt(action, groupKey);
        Digest digest = Digest.sign(getLastDigest(), encryptedAction, groupId, ecc);

        PeerAction peerAction = new PeerAction(encryptedAction, peer, groupId, digest);
        peerActionSequence.add(peerAction);
    }

    public void add(PeerAction peerAction) {
        peerActionSequence.add(peerAction);
    }

    public List<DigestViolation> verify() {
        Digest previousDigest = null;
        List<DigestViolation> digestViolations = new ArrayList<>();

        for(int i = 0; i < peerActionSequence.size(); i++) {
            PeerAction peerAction = peerActionSequence.get(i);

            byte[] peerPublicKey = HEX_ENCODER.decode(peerAction.getPeer().getHexPublicKey());
            boolean isValid = peerAction.getDigest().verify(
                    previousDigest,
                    peerAction.getEncryptedAction(),
                    peerAction.getGroupId(),
                    peerPublicKey);

            if(!isValid) {
                DigestViolation digestViolation = new DigestViolation(i, peerAction);
                logger.severe(digestViolation.toString());
                digestViolations.add(digestViolation);
            }
            previousDigest = peerAction.getDigest();
        }

        return digestViolations;
    }

    public String encode() {
        return BASE64_ENCODER.encodeToString(this.toString());
    }

    public static History decode(String encodedHistory) {
        String sJHistory = BASE64_ENCODER.decodeToString(encodedHistory);
        JsonArray jHistory = new JsonParser().parse(sJHistory).getAsJsonArray();
        Iterator<JsonElement> iterator = jHistory.iterator();

        History h = new History();

        while (iterator.hasNext()) {
            JsonArray jPeerAction = iterator.next().getAsJsonArray();
            PeerAction peerAction = PeerAction.fromJsonArray(jPeerAction);
            h.add(peerAction);
        }

        return h;
    }

    public List<ActionWrapper> decrypt(Keyring kr) {
        List<ActionWrapper> actions = new ArrayList<>();

        for(PeerAction peerAction : peerActionSequence) {
            try {
                Action action = peerAction.getEncryptedAction().decrypt(kr.retrieveGroupKey(peerAction.getGroupId()));
                actions.add(new ActionWrapper(action, peerAction.getPeer(), peerAction.getGroupId()));
            } catch (GroupIdException e) {
                actions.add(new ActionWrapper(new Action("hidden", "hidden", "hidden"), peerAction.getPeer(), peerAction.getGroupId()));
            } catch (PrivateKeyDecryptionException | BadPassphraseException e) {
                e.printStackTrace();
            }
        }

        return actions;
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

    public Digest getLastDigest() {
        try {
            return peerActionSequence.getLast().getDigest();
        } catch (NoSuchElementException e) {
            return null;
        }
    }

    public int getSize() {
        return peerActionSequence.size();
    }
}
