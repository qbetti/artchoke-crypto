package ca.uqac.lif.artichoke.encoding;

import org.junit.Test;

import static org.junit.Assert.*;

public class EncoderTest {

    private final static String TO_TEST = "Hello, world!";
    private final static String B64_TO_TEST = "SGVsbG8sIHdvcmxkIQ==";
    private final static String HEX_TO_TEST = "48656c6c6f2c20776f726c6421";

    private void testEncoder(Encoder encoder, byte[] expectedEncoded) {
        byte[] toTest = TO_TEST.getBytes();

        byte[] encoded = encoder.encode(toTest);
        assertArrayEquals(expectedEncoded, encoded);
        byte[] decoded = encoder.decode(encoded);
        assertArrayEquals(toTest, decoded);
    }

    private void testStringEncoder(StringEncoder encoder, String expectedEncoded) {
        String toTest = TO_TEST;

        String encoded0 = encoder.encodeToString(toTest);
        assertEquals(expectedEncoded, encoded0);
        String decoded0 = encoder.decodeToString(encoded0);
        assertEquals(toTest, decoded0);

        String encoded1 = encoder.encodeToString(toTest.getBytes());
        assertEquals(expectedEncoded, encoded1);
        String copyDecoded = encoder.decodeToString(encoded1.getBytes());
        assertEquals(toTest, copyDecoded);

        byte[] encoded2 = encoder.encode(toTest);
        assertArrayEquals(expectedEncoded.getBytes(), encoded2);
        byte[] decoded2 = encoder.decode(new String(encoded2));
        assertArrayEquals(toTest.getBytes(), decoded2);
    }

    @Test
    public void testBase64() {
        StringEncoder encoder = Base64Encoder.getInstance();
        testEncoder(encoder, B64_TO_TEST.getBytes());
        testStringEncoder(encoder, B64_TO_TEST);
    }

    @Test
    public void testHex() {
        StringEncoder encoder = HexEncoder.getInstance();
        testEncoder(encoder, HEX_TO_TEST.getBytes());
        testStringEncoder(encoder, HEX_TO_TEST);
    }

}