package ca.uqac.lif.artichoke;

import ca.uqac.lif.artichoke.crypto.EccEncryption;
import ca.uqac.lif.artichoke.crypto.EccSignature;
import ca.uqac.lif.artichoke.encoding.Base64Encoder;
import ca.uqac.lif.artichoke.exceptions.BadPassphraseException;
import ca.uqac.lif.artichoke.exceptions.PrivateKeyDecryptionException;
import ca.uqac.lif.artichoke.keyring.Keyring;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Digest {

    private byte[] signedData;

    public Digest(byte[] data) {
        this.signedData = data;
    }

    private static byte[] computeHash(Digest lastDigest, EncryptedAction encryptedAction, String groupId) {
        if(lastDigest == null) {
            lastDigest = new Digest(new byte[0]);
        }

        byte[] toHash = new byte[lastDigest.signedData.length + encryptedAction.getData().length + groupId.getBytes().length];
        System.arraycopy(lastDigest.signedData, 0, toHash, 0, lastDigest.signedData.length);
        System.arraycopy(encryptedAction.getData(),0, toHash, lastDigest.signedData.length, encryptedAction.getData().length);
        System.arraycopy(groupId.getBytes(), 0, toHash, lastDigest.signedData.length + encryptedAction.getData().length, groupId.getBytes().length);

        MessageDigest messageDigest = null;
        try {
            messageDigest = MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            System.exit(-1);
        }

        return messageDigest.digest(toHash);
    }


    public static Digest sign(Digest lastDigest, EncryptedAction encryptedAction, String groupId, EccEncryption ecc) {
        byte[] hash = computeHash(lastDigest, encryptedAction, groupId);
        EccSignature signature = ecc.sign(hash);
        return new Digest(signature.getBytes());
    }

    public static Digest sign(Digest lastDigest, EncryptedAction encryptedAction, String groupId, Keyring kr) {
        try {
            byte[] hash = computeHash(lastDigest, encryptedAction, groupId);
            byte[] signature = kr.sign(hash);
            return new Digest(signature);
        } catch (PrivateKeyDecryptionException | BadPassphraseException e) {
            e.printStackTrace();
        }
        return null;
    }

    public boolean verify(Digest lastDigest, EncryptedAction encryptedAction, String groupId, byte[] publicKey) {
        byte[] hash = computeHash(lastDigest, encryptedAction, groupId);
        return EccEncryption.verifySignature(signedData, hash, publicKey);
    }



    public static Digest decode(String encodedDigest) {
        return new Digest(Base64Encoder.getInstance().decode(encodedDigest));
    }

    public String encode() {
        return Base64Encoder.getInstance().encodeToString(signedData);
    }
}
