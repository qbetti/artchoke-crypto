package ca.uqac.lif.artichoke;

import ca.uqac.lif.artichoke.encoding.Base64Encoder;
import ca.uqac.lif.artichoke.encoding.StringEncoder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonParser;

import java.util.logging.Logger;

public class Action {

    private final static Logger logger = Logger.getLogger(Action.class.getName());

    public static final StringEncoder BASE64_ENCODER = Base64Encoder.getInstance();

    private String target;
    private String type;
    private String value;

    public Action(String target, String type, String value) {
        this.target = target;
        this.type = type;
        this.value = value;
    }

    public String encode() {
        return this.toString();
    }

    public static Action decode(String encodedAction) {
        JsonElement jAction = new JsonParser().parse(encodedAction);
        JsonArray array = jAction.getAsJsonArray();
        return new Action(array.get(0).getAsString(), array.get(1).getAsString(), array.get(2).getAsString());
    }

    @Override
    public String toString() {
        JsonArray array = new JsonArray();
        array.add(target);
        array.add(type);
        array.add(value);
        return array.toString();
    }
}
