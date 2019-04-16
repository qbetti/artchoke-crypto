package ca.uqac.lif.artichoke.crypto;

import ca.uqac.lif.artichoke.encoding.Base64Encoder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Test;

import java.security.KeyPair;
import java.security.Security;

import static org.junit.Assert.*;

public class EccEncryptionTest {

    private static final byte[] DATA = "This is data to be signed!".getBytes();
    private static final byte[] WRONG_DATA = "This is wrong data to be signed!".getBytes();

    private EccEncryption ecc;
    private EccEncryption otherEcc;

    @BeforeClass
    public static void init() {
        Security.addProvider(new BouncyCastleProvider());
    }

    public EccEncryptionTest() {
        this.ecc = new EccEncryption();
        this.otherEcc = new EccEncryption();
    }

    @Test
    public void testGenerateKeys() {
        KeyPair keyPair = EccEncryption.generateNewKeys();
        assertNotNull(keyPair);
        assertNotNull(keyPair.getPrivate());
        assertNotNull(keyPair.getPublic());
    }

    @Test
    public void testKeyGetters() {
        KeyPair keyPair = EccEncryption.generateNewKeys();
        EccEncryption ecc = new EccEncryption(keyPair);

        assertEquals(keyPair.getPublic(), ecc.getPublicKey());
        assertEquals(keyPair.getPrivate(), ecc.getPrivateKey());
    }

    @Test
    public void testSignature() {
        EccSignature signature = ecc.sign(DATA);
        assertTrue(ecc.verifySignature(signature, DATA));
        assertFalse(ecc.verifySignature(signature, WRONG_DATA));

        EccSignature otherSignature = otherEcc.sign(DATA);
        assertFalse(ecc.verifySignature(otherSignature.getBytes(), DATA));
    }

    @Test
    public void testKeyEncoding() {
        EccSignature signature = ecc.sign(DATA);

        EccEncryption eccWithHexKeys = new EccEncryption(ecc.encodePrivateKey(), ecc.encodePublicKey());
        assertTrue(eccWithHexKeys.verifySignature(signature, DATA));

        Base64Encoder b64 = Base64Encoder.getInstance();
        EccEncryption eccWithB64Keys = new EccEncryption(ecc.encodePrivateKey(b64), ecc.encodePublicKey(b64), b64);
        assertTrue(eccWithB64Keys.verifySignature(signature, DATA));
    }

    @Test
    public void testWithOtherCurve() {
        String curveName = "prime256v1";
        EccEncryption eccWithOtherCurve = new EccEncryption(curveName);
        EccSignature signature = eccWithOtherCurve.sign(DATA);

        assertTrue(EccEncryption.verifySignature(signature.getBytes(), DATA, eccWithOtherCurve.getPublicKeyBytes(), curveName));

        EccEncryption eccWithDefaultCurve = new EccEncryption(
                eccWithOtherCurve.getPrivateKeyBytes(), // private keys share the same bytes
                ecc.getPublicKeyBytes() // but curve used for encryption is different, and so is the EC point
        );
        // so signature should be invalid
        assertFalse(eccWithDefaultCurve.verifySignature(signature, DATA));
    }


}