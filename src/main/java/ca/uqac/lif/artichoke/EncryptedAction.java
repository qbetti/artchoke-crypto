package ca.uqac.lif.artichoke;

import ca.uqac.lif.artichoke.crypto.AesCtrCipher;
import ca.uqac.lif.artichoke.crypto.AesCtrEncryption;
import ca.uqac.lif.artichoke.encoding.Base64Encoder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;

public class EncryptedAction {

    public static final Base64Encoder BASE64_ENCODER = Base64Encoder.getInstance();

    private byte[] data;
    private byte[] iv;

    public EncryptedAction(byte[] data, byte[] iv) {
        this.data = data;
        this.iv = iv;
    }

    public static EncryptedAction encrypt(Action action, byte[] groupKey) {
        AesCtrEncryption aes = new AesCtrEncryption(groupKey);
        AesCtrCipher cipher = aes.encrypt(action.encode().getBytes());

        return new EncryptedAction(cipher.getDataBytes(), cipher.getIv());
    }

    public Action decrypt(byte[] groupKey) {
        AesCtrEncryption aes = new AesCtrEncryption(groupKey);
        AesCtrCipher cipher = aes.decrypt(this.data, this.iv);

        return Action.decode(new String(cipher.getDataBytes()));
    }


    public String encode() {
        return this.toString();
    }

    public static EncryptedAction decode(String encodedEncryptedAction) {
        JsonElement jEncryptedAction = new JsonParser().parse(encodedEncryptedAction);
        JsonArray array = jEncryptedAction.getAsJsonArray();
        return fromJsonArray(array);
    }

    public JsonArray toJsonArray() {
        JsonArray array = new JsonArray();
        array.add(BASE64_ENCODER.encodeToString(data));
        array.add(BASE64_ENCODER.encodeToString(iv));
        return array;
    }

    public static EncryptedAction fromJsonArray(JsonArray jsonArray) {
        return new EncryptedAction(
                BASE64_ENCODER.decode(jsonArray.get(0).getAsString()),
                BASE64_ENCODER.decode(jsonArray.get(1).getAsString()));
    }

    @Override
    public String toString() {
        return toJsonArray().toString();
    }

    public byte[] getData() {
        return data;
    }
}
