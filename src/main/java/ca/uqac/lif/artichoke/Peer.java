package ca.uqac.lif.artichoke;

import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;


public class Peer {
    private String name;
    private String hexPublicKey;

    public Peer(String name, String hexPublicKey) {
        this.name = name;
        this.hexPublicKey = hexPublicKey;
    }

    public String encode() {
        return this.toString();
    }

    public static Peer decode(String encodedPeer) {
        JsonElement jEncodedPeer = new JsonParser().parse(encodedPeer);
        JsonArray array = jEncodedPeer.getAsJsonArray();
        return fromJsonArray(array);
    }

    public static Peer fromJsonArray(JsonArray jsonArray) {
        return new Peer(
                jsonArray.get(0).getAsString(),
                jsonArray.get(1).getAsString()
        );
    }

    public JsonArray toJsonArray() {
        JsonArray array = new JsonArray();
        array.add(name);
        array.add(hexPublicKey);
        return array;
    }

    @Override
    public String toString() {
        return toJsonArray().toString();
    }

    public String getHexPublicKey() {
        return hexPublicKey;
    }

    public String getName() {
        return name;
    }
}
