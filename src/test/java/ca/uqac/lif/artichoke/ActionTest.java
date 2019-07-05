package ca.uqac.lif.artichoke;

import org.junit.Test;

import static org.junit.Assert.*;

public class ActionTest {


    @Test
    public void testEncodeDecode() {
        Action action = new Action("first_name", "write", "Quentin");
        System.out.println(action);
        String b64Action = action.encode();
        System.out.println(b64Action);
        Action decodedAction = Action.decode(b64Action);
        System.out.println(decodedAction);
        assertEquals(action.toString(), decodedAction.toString());
    }

}