package ca.uqac.lif.artichoke.crypto;

import ca.uqac.lif.artichoke.encoding.HexEncoder;
import ca.uqac.lif.artichoke.encoding.StringEncoder;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.jce.spec.ECPublicKeySpec;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.security.*;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;


/**
 * Provides a wrapper around elliptic curve signature generation/verification from BouncyCastle
 * and key pair generation.
 * The signing algorithm used is {@value #SIGNATURE_ALGO}, which is the ECDSA algorithm
 * with data hash function SHA1.
 * The default curve (used in case none is specified in the different constructors/methods) for key
 * generation, signature and verification is the {@value DEFAULT_CURVE_NAME} curve.
 */
public class EccEncryption {

    /**
     * Elliptic curve algorithm
     */
    public static final String EC = "EC";

    /**
     * Full algorithm for signing
     */
    private static final String SIGNATURE_ALGO = "SHA256withECDSA";

    /**
     * The curve used for key generation and signing
     */
    public static final String DEFAULT_CURVE_NAME = "secp256k1";

    /**
     * The size in bytes of the private key
     */
    public static final int PRIVATE_KEY_SIZE = 32; // in bytes

    /**
     * The private key
     */
    private ECPrivateKey privateKey;

    /**
     * The public key
     */
    private ECPublicKey publicKey;


    /**
     * Constructor by specifying the private and public keys
     * @param privateKey the private key (should be castable to {@link ECPrivateKey})
     * @param publicKey the public key (should be castable to {@link ECPublicKey})
     */
    public EccEncryption(PrivateKey privateKey, PublicKey publicKey) {
        this.privateKey = (ECPrivateKey) privateKey;
        this.publicKey = (ECPublicKey) publicKey;
    }

    /**
     * Constructor by specifying the private and public keys' bytes for the specified curve
     * @param privateKey the private key's integer's bytes
     * @param publicKey the public key's EC point coordinate's bytes
     * @param curveName the name of the curve
     */
    public EccEncryption(byte[] privateKey, byte[] publicKey, String curveName) {
        this.privateKey = toPrivateKey(privateKey, curveName);
        this.publicKey = toPublicKey(publicKey, curveName);
    }

    /**
     * Constructor by specifying the private and public keys' bytes for {@value DEFAULT_CURVE_NAME} curve
     * @param privateKey the private key's integer's bytes
     * @param publicKey the public key's EC point coordinate's bytes
     */
    public EccEncryption(byte[] privateKey, byte[] publicKey) {
        this(privateKey, publicKey, DEFAULT_CURVE_NAME);
    }

    /**
     * Constructor by specifying encoded representations of both private and public keys of the specified curve
     * @param encodedPrivateKey the encoded private key's integer's bytes
     * @param encodedPublicKey the encoded public key's EC point coordinate's bytes
     * @param encoder the encoder used to encode the keys
     * @param curveName the name of the curve
     */
    public EccEncryption(String encodedPrivateKey, String encodedPublicKey, StringEncoder encoder, String curveName) {
        this(encoder.decode(encodedPrivateKey), encoder.decode(encodedPublicKey), curveName);
    }

    /**
     * Constructor by specifying encoded representations of both private and public keys of the {@value DEFAULT_CURVE_NAME} curve
     * @param encodedPrivateKey the encoded private key's integer's bytes
     * @param encodedPublicKey the encoded public key's EC point coordinate's bytes
     * @param encoder the encoder used to encode the keys
     */
    public EccEncryption(String encodedPrivateKey, String encodedPublicKey, StringEncoder encoder) {
        this(encoder.decode(encodedPrivateKey), encoder.decode(encodedPublicKey), DEFAULT_CURVE_NAME);
    }

    /**
     * Constructor by specifying the private and public keys from the {@value DEFAULT_CURVE_NAME} curve
     * @param hexPrivateKey the hex-encoded private key's integer's bytes
     * @param hexPublicKey the hex-encoded public key's EC point coordinate's bytes
     */
    public EccEncryption(String hexPrivateKey, String hexPublicKey) {
        this(hexPrivateKey, hexPublicKey, HexEncoder.getInstance(), DEFAULT_CURVE_NAME);
    }

    /**
     * Constructor by specifying the key pair
     * @param keyPair the key pair (should hold EC keys)
     */
    public EccEncryption(KeyPair keyPair) {
        this(keyPair.getPrivate(), keyPair.getPublic());
    }

    /**
     * Constructor generating a new EC key pair for the {@value DEFAULT_CURVE_NAME} curve
     */
    public EccEncryption() {
        this(DEFAULT_CURVE_NAME);
    }

    /**
     * Constructor generating a new EC key pair for a specified curve
     * @param curveName the name of the curve
     */
    public EccEncryption(String curveName) {
        this(generateNewKeys(curveName));
    }

    /**
     * Generates a new EC key pair for the specified elliptic curve
     * @param curveName the name of the curve
     */
    public static KeyPair generateNewKeys(String curveName) {
        try {
            KeyPairGenerator gen = KeyPairGenerator.getInstance(EC, "BC");
            gen.initialize(new ECGenParameterSpec(curveName));
            return gen.generateKeyPair();

        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException e) {
            e.printStackTrace();
            System.exit(-1);
            return null;
        }
    }

    /**
     * Generates a new EC key pair for the {@value DEFAULT_CURVE_NAME} curve
     */
    public static KeyPair generateNewKeys() {
        return generateNewKeys(DEFAULT_CURVE_NAME);
    }

    /**
     * Signs data using {@value SIGNATURE_ALGO}
     * @param data the data to use for signature
     * @return the signature, or null if something goes wrong
     */
    public EccSignature sign(byte[] data) {
        Signature ecdsa = null;
        try {
            ecdsa = Signature.getInstance(SIGNATURE_ALGO);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        try {
            ecdsa.initSign(privateKey);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        try {
            ecdsa.update(data);
        } catch (SignatureException e) {
            e.printStackTrace();
        }
        try {
            return new EccSignature(ecdsa.sign());
        } catch (SignatureException e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Verifies a signature with the signed data
     * @param signature the signature
     * @param data the expected signed data
     * @return true if the signature is correct, false otherwise
     */
    public boolean verifySignature(EccSignature signature, byte[] data) {
        return verifySignature(signature.getBytes(), data);
    }


    /**
     * Verifies a signature with the signed data
     * @param signature the signature
     * @param data the expected signed data
     * @return true if the signature is correct, false otherwise
     */
    public boolean verifySignature(byte[] signature, byte[] data) {
        return verifySignature(signature, data, publicKey);
    }

    /**
     * Verifies a signature over a specified curve
     * @param signature the bytes of the signature
     * @param data the expected bytes of the signed data
     * @param publicKeyBytes the public key bytes (ONLY the EC point coordinates) corresponding to the signature
     * @param curveName the name of the curve for the provided key
     * @return true if the signature is verified, false otherwise
     */
    public static boolean verifySignature(byte[] signature, byte[] data, byte[] publicKeyBytes, String curveName) {
        return verifySignature(signature, data, toPublicKey(publicKeyBytes, curveName));
    }

    public static boolean verifySignature(byte[] signature, byte[] data, byte[] publicKeyBytes) {
        return verifySignature(signature, data, toPublicKey(publicKeyBytes, DEFAULT_CURVE_NAME));
    }

    /**
     * Verifies a signature over a specified curve
     * @param signature the bytes of the signature
     * @param data the expected bytes of the signed data
     * @param publicKey the expected public key corresponding to the signature
     * @return true if the signature is verified, false otherwise
     */
    public static boolean verifySignature(byte[] signature, byte[] data, PublicKey publicKey) {
        Signature ecdsa = null;
        try {
            ecdsa = Signature.getInstance(SIGNATURE_ALGO);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        try {
            ecdsa.initVerify(publicKey);
        } catch (InvalidKeyException e) {
            e.printStackTrace();
        }
        try {
            ecdsa.update(data);
        } catch (SignatureException e) {
            e.printStackTrace();
        }
        try {
            return ecdsa.verify(signature);
        } catch (SignatureException e) {
            e.printStackTrace();
            return false;
        }
    }

    /**
     * Formats a private key so that it corresponds to a 32-byte long array
     * @param privateKey the private key to format
     * @return a 32-byte long array containing the key
     */
    private static byte[] formatPrivateKey(ECPrivateKey privateKey) {
        return formatPrivateKey(privateKey.getD().toByteArray());
    }

    /**
     * Formats a private key so that it corresponds to a 32-byte long array
     * @param privateKeyBytes the private key's integer bytes
     * @return a 32-byte long array containing the key
     */
    private static byte[] formatPrivateKey(byte[] privateKeyBytes) {
        if(PRIVATE_KEY_SIZE < privateKeyBytes.length) {
            // if privateKey.getD() is high, it will have 32 significant bytes and one signing byte (=0, because D is always positive)
            // thus we trim this signing byte to have an exactly 32 byte-long key
            return Arrays.copyOfRange(privateKeyBytes, 1, privateKeyBytes.length );

        } else if (privateKeyBytes.length < PRIVATE_KEY_SIZE) {
            // If privateKey.getD() is too small, BigInteger#toByteArray() will return only 31 or less bytes
            // This is because BigInteger#toByteArray() generates the smallest byte array that can
            // represent the BigInteger, which means that on a 32-byte key, if the first bytes are `0`,
            // privateKey.getD().toByteArray() will trim them, so we re-insert them at the beginning of the byte array in order
            // to have a 32-byte key.
            int missingZeroByteNb = PRIVATE_KEY_SIZE - privateKeyBytes.length;

            byte[] formattedPrivateKeyBytes = new byte[PRIVATE_KEY_SIZE];
            Arrays.fill(formattedPrivateKeyBytes, 0, missingZeroByteNb - 1, (byte) 0);
            System.arraycopy(privateKeyBytes, 0, formattedPrivateKeyBytes, missingZeroByteNb, privateKeyBytes.length);

            return formattedPrivateKeyBytes;
        }
        else{
            return privateKeyBytes;
        }
    }

    /**
     * Converts a byte array to a proper EC private key
     * @param privateKeyBytes the bytes of the private key's integer
     * @return the converted private key
     */
    private static ECPrivateKey toPrivateKey(byte[] privateKeyBytes, String curveName) {
        if(privateKeyBytes == null || privateKeyBytes.length == 0)
            return null;

        ECParameterSpec params = ECNamedCurveTable.getParameterSpec(curveName);

        BigInteger d = new BigInteger(formatPrivateKey(privateKeyBytes));
        ECPrivateKeySpec privateKeySpec = new ECPrivateKeySpec(d, params);

        try {
            return (ECPrivateKey) getKeyFactory().generatePrivate(privateKeySpec);
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Converts a byte array to a proper EC public key
     * @param publicKeyBytes the bytes of the public key's ECC point coordinates
     * @return the converted public key
     */
    private static ECPublicKey toPublicKey(byte[] publicKeyBytes, String curveName) {
        ECParameterSpec params = ECNamedCurveTable.getParameterSpec(curveName);

        ECPoint q = params.getCurve().decodePoint(publicKeyBytes);
        ECPublicKeySpec publicKeySpec = new ECPublicKeySpec(q, params);

        try {
            return (ECPublicKey) getKeyFactory().generatePublic(publicKeySpec);
        } catch (InvalidKeySpecException e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Returns the BouncyCastle EC key factory
     * @return the BouncyCastle EC key factory
     */
    private static KeyFactory getKeyFactory() {
        try {
            return KeyFactory.getInstance(EC, "BC");
        } catch (NoSuchAlgorithmException | NoSuchProviderException e) {
            e.printStackTrace();
            System.exit(-1);
            return null;
        }
    }

    /**
     * Encodes the private key
     * @param encoder the encoder to use
     * @return the encoded the private key's integer bytes
     */
    public String encodePrivateKey(StringEncoder encoder) {
        return encoder.encodeToString(getPrivateKeyBytes());
    }

    /**
     * Encodes the private key in hexadecimal
     * @return the private key's integer bytes encoded in hexadecimal
     */
    public String encodePrivateKey() {
        return encodePrivateKey(HexEncoder.getInstance());
    }

    /**
     * Encodes the public key
     * @param encoder the encoder to use
     * @return the encoded public key's EC point coordinates' bytes
     */
    public String encodePublicKey(StringEncoder encoder) {
        return encoder.encodeToString(publicKey.getQ().getEncoded(true));
    }

    /**
     * Encodes the public key in hexadecimal
     * @return the public key's EC point coordinates' bytes in hexadecimal
     */
    public String encodePublicKey() {
        return encodePublicKey(HexEncoder.getInstance());
    }

    /**
     * Returns the private key
     * @return the private key
     */
    public ECPrivateKey getPrivateKey() {
        return privateKey;
    }

    /**
     * Returns the formatted private key bytes
     * @return the formatted private key bytes (ONLY the integer bytes)
     */
    public byte[] getPrivateKeyBytes() {
        return formatPrivateKey(privateKey);
    }

    /**
     * Returns the public key
     * @return the public key
     */
    public ECPublicKey getPublicKey() {
        return publicKey;
    }

    /**
     * Retunrs the public key's bytes
     * @return the public key's bytes (ONLY the EC point coordinates)
     */
    public byte[] getPublicKeyBytes() {
        return publicKey.getQ().getEncoded(false);
    }
}

