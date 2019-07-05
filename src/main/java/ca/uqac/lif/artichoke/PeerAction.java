package ca.uqac.lif.artichoke;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;

public class PeerAction {

    private EncryptedAction encryptedAction;
    private Peer peer;
    private String groupId;
    private Digest digest;


    public PeerAction(EncryptedAction encryptedAction, Peer peer, String groupId, Digest digest) {
        this.encryptedAction = encryptedAction;
        this.peer = peer;
        this.groupId = groupId;
        this.digest = digest;
    }

    public String encode() {
        return toString();
    }

    public static PeerAction decode(String encodedPeerAction) {
        JsonElement jEncodedPeerAction = new JsonParser().parse(encodedPeerAction);
        JsonArray array = jEncodedPeerAction.getAsJsonArray();
        return fromJsonArray(array);
    }

    public JsonArray toJsonArray() {
        JsonArray array = new JsonArray();
        array.add(encryptedAction.toJsonArray());
        array.add(peer.toJsonArray());
        array.add(groupId);
        array.add(digest.encode());
        return array;
    }

    public static PeerAction fromJsonArray(JsonArray jsonArray) {
        return new PeerAction(
                EncryptedAction.fromJsonArray(jsonArray.get(0).getAsJsonArray()),
                Peer.fromJsonArray(jsonArray.get(1).getAsJsonArray()),
                jsonArray.get(2).getAsString(),
                Digest.decode(jsonArray.get(3).getAsString())
        );
    }

    public EncryptedAction getEncryptedAction() {
        return encryptedAction;
    }

    public Peer getPeer() {
        return peer;
    }

    public Digest getDigest() {
        return digest;
    }

    public String getGroupId() {
        return groupId;
    }

    @Override
    public String toString() {

        return toJsonArray().toString();
    }
}
