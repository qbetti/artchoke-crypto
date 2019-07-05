package ca.uqac.lif.artichoke;

import com.google.gson.JsonArray;

public class ActionWrapper {

    private Action action;
    private Peer peer;
    private String groupId;

    public ActionWrapper(Action action, Peer peer, String groupId) {
        this.action = action;
        this.peer = peer;
        this.groupId = groupId;
    }

    public Action getAction() {
        return action;
    }

    public Peer getPeer() {
        return peer;
    }

    public String getGroupId() {
        return groupId;
    }

    public JsonArray toJsonArray() {
        JsonArray jsonArray = new JsonArray();
        jsonArray.add(action.toJsonArray());
        jsonArray.add(peer.toJsonArray());
        jsonArray.add(groupId);

        return jsonArray;
    }

    @Override
    public String toString() {
        return toJsonArray().toString();
    }
}
