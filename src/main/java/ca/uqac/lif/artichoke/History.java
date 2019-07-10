package ca.uqac.lif.artichoke;

import ca.uqac.lif.artichoke.encoding.Base64Encoder;
import ca.uqac.lif.artichoke.encoding.HexEncoder;
import ca.uqac.lif.artichoke.exceptions.BadPassphraseException;
import ca.uqac.lif.artichoke.exceptions.GroupIdException;
import ca.uqac.lif.artichoke.exceptions.PrivateKeyDecryptionException;
import ca.uqac.lif.artichoke.keyring.Keyring;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;

import java.util.*;
import java.util.logging.Logger;

/**
 * Contains and provided methods to interact with a peer-action sequence
 */
public class History {

    /**
     * Logger for this class
     */
    private final static Logger logger = Logger.getLogger(History.class.getName());

    /**
     * Base64 encoder, used for encrypted data and digests
     */
    private final static Base64Encoder BASE64_ENCODER = Base64Encoder.getInstance();

    /**
     * Hexadecimal encoder, used for peers' public keys
     */
    private final static HexEncoder HEX_ENCODER = HexEncoder.getInstance();

    /**
     * The peer-action sequence
     */
    private LinkedList<PeerAction> peerActionSequence;


    /**
     * Constructs a new history with an empty peer-action sequence
     */
    public History() {
        this.peerActionSequence = new LinkedList<>();
    }

    /**
     * Encrypts an action, computes the digest, and add the resulting peer-action to the peer-action sequence
     * @param action the atomic action
     * @param peer the peer performing the action
     * @param groupId the id of the group on behalf of which is made the action
     * @param groupKey the key of the group
     * @param privateKey the user's private key bytes to sign the digest
     */
    public void add(Action action, Peer peer, String groupId, byte[] groupKey,  byte[] privateKey) {
        EncryptedAction encryptedAction = EncryptedAction.encrypt(action, groupKey);
        Digest digest = Digest.sign(getLastDigest(), encryptedAction, groupId, privateKey);

        PeerAction peerAction = new PeerAction(encryptedAction, peer, groupId, digest);
        peerActionSequence.add(peerAction);
    }

    /**
     * Encrypts an action, computes the digest, and add the resulting peer-action to the peer-action
     * using info stored in the keyring
     * @param action the atomic action
     * @param peer the peer performing the action
     * @param groupId the id of the group on behalf of which is made the action
     * @param kr the keyring where the user's private and group keys are store
     * @param passphrase the passphrase to unlock the keyring
     * @throws PrivateKeyDecryptionException if there is a problem during private key decryption
     * @throws GroupIdException if the specified group id is absent from the keyring
     * @throws BadPassphraseException if the passphrase for this keyring is incorrect
     */
    public void add(Action action, Peer peer, String groupId, Keyring kr, String passphrase)
            throws PrivateKeyDecryptionException, GroupIdException, BadPassphraseException {
        EncryptedAction encryptedAction = EncryptedAction.encrypt(action, kr.retrieveGroupKey(passphrase, groupId));
        Digest digest = Digest.sign(getLastDigest(), encryptedAction, groupId, kr);

        PeerAction peerAction = new PeerAction(encryptedAction, peer, groupId, digest);
        peerActionSequence.add(peerAction);
    }

    /**
     * Encrypts an action, computes the digest, and add the resulting peer-action to the peer-action
     * using info stored in the keyring
     * @param action the atomic action
     * @param peer the peer performing the action
     * @param groupId the id of the group on behalf of which is made the action
     * @param kr the keyring where the user's private and group keys are store
     * @throws PrivateKeyDecryptionException if there is a problem during private key decryption
     * @throws GroupIdException if the specified group id is absent from the keyring
     * @throws BadPassphraseException if the passphrase for this keyring is incorrect or not provided
     */
    public void add(Action action, Peer peer, String groupId, Keyring kr)
            throws PrivateKeyDecryptionException, GroupIdException, BadPassphraseException {
        add(action, peer, groupId, kr, null);
    }

    /**
     * Add a peer-action the history peer-action sequence
     * @param peerAction the peer-action to add
     */
    public void add(PeerAction peerAction) {
        peerActionSequence.add(peerAction);
    }

    /**
     * Verifies if there is any violation in the building of the peer-action sequence
     * @return a list of the violations if any
     */
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

    /**
     * Decrypts and returns actions stored in the peer-action sequence with available groups' keys in the provided keyring
     * @param kr the keyring containing the group keys
     * @return the list of decripted action. If an action cannot be decrypted (group key is missing),
     *          an action with "hidden" values for target, type and value, is put.
     */
    public List<WrappedAction> decrypt(Keyring kr) {
        List<WrappedAction> actions = new ArrayList<>();

        for(PeerAction peerAction : peerActionSequence) {
            Action action;
            try {
                action = peerAction.getEncryptedAction().decrypt(kr.retrieveGroupKey(peerAction.getGroupId()));
            } catch (GroupIdException e) {
                action = new Action("hidden", "hidden", "hidden");
            } catch (PrivateKeyDecryptionException | BadPassphraseException e) {
                action = new Action("hidden", "hidden", "hidden");
                e.printStackTrace();
            }
            actions.add(new WrappedAction(action, peerAction.getPeer(), peerAction.getGroupId()));
        }

        return actions;
    }

    /**
     * Decrypts and returns actions stored in the peer-action sequence with provided group keys
     * @param keysByGroupId the map from group ids to their key group
     * @return the list of decripted action. If an action cannot be decrypted (group key is missing),
     *          an action with "hidden" values for target, type and value, is put.
     */
    public List<WrappedAction> decrypt(Map<String, byte[]> keysByGroupId) {
        if(keysByGroupId == null)
            return null;

        List<WrappedAction> actions = new ArrayList<>();

        for(PeerAction peerAction : peerActionSequence) {
            byte[] groupKey = keysByGroupId.get(peerAction.getGroupId());
            Action action;
            if(groupKey != null)
                action = peerAction.getEncryptedAction().decrypt(groupKey);
            else
                action = new Action("hidden", "hidden", "hidden");

            actions.add(new WrappedAction(action, peerAction.getPeer(), peerAction.getGroupId()));
        }

        return actions;
    }

    /**
     * Returns the digest of the last peer-action of this peer-action sequence, null if none
     * @return the digest of the last peer-action of this peer-action sequence, null if none
     */
    public Digest getLastDigest() {
        try {
            return peerActionSequence.getLast().getDigest();
        } catch (NoSuchElementException e) {
            return null;
        }
    }

    /**
     * Returns the number of peer-actions contained in the sequence
     * @return the number of peer-actions contained in the sequence
     */
    public int getSize() {
        return peerActionSequence.size();
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
}
