package ca.uqac.lif.artichoke.keyring;


import ca.uqac.lif.artichoke.crypto.*;
import ca.uqac.lif.artichoke.encoding.HexEncoder;
import ca.uqac.lif.artichoke.encoding.StringEncoder;
import ca.uqac.lif.artichoke.exceptions.*;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;

import javax.crypto.SecretKey;
import java.io.*;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;


/**
 * A Keyring is an object containing information about a user's elliptic curve (EC) key pair,
 * and the groups' info (id) and secret key he belongs to.
 * The user's private key and all the groups' secret key are encrypted, making this keyring local or online
 * storage secure.
 * The user's private key AES-encrypted by the key derived from the keyring passphrase, that is specified
 * at the keyring creation.
 * The passphrase key derivation is done using the Key Derivation Function SCrypt, and MUST NOT BE FORGOTTEN
 * because it cannot be recovered. If it were lost, everything stored in the keyring would be unusable.
 * The groups' secret keys are then AES-encrypted using the user's private key as the AES secret key.
 * The AES mode used for encryption/decryption is the counter mode, which means that each encrypted key is followed
 * by the corresponding initialisation vector (IV)
 */
public class Keyring {

    private static final StringEncoder HEX_ENCODER = HexEncoder.getInstance();

    /**
     * JSON key for the SCrypt salt
     */
    private static final String JKEY_SCRYPT_SALT = "salt";

    /**
     * JSON key for the user's public key
     */
    private static final String JKEY_PUBLIC_KEY = "publicKey";

    /**
     * JSON key for the user's private key
     */
    private static final String JKEY_PRIVATE_KEY = "privateKey";

    /**
     * JSON key for key's cipher text
     */
    private static final String JKEY_CIPHER_TEXT = "cipherText";

    /**
     * JSON key for key's cipher IV
     */
    private static final String JKEY_IV = "iv";

    /**
     * JSON key for the groups the user belongs to
     */
    private static final String JKEY_GROUPS = "groups";

    /**
     * JSON key for a group's id
     */
    private static final String JKEY_GROUP_ID = "id";


    /**
     * The user's hexadecimal public key
     */
    private String hexPublicKey;

    /**
     * The user's hexadecimal private key cipher text
     */
    private String hexEncryptedPrivateKey;

    /**
     * The hexadecimal user's private key's cipher IV
     */
    private String hexIvPrivateKey;

    /**
     * The SCrypt KDF salt
     */
    private String hexScryptSalt;

    /**
     * The SCrypt derived key kept in memory for performance (null if not kept in memory)
     */
    private byte[] derivedKey;

    /**
     * The maps containing the groups the user belongs to listed by group ID
     */
    private HashMap<String, KeyringGroup> groupsById;


    /**
     * Default constructor
     */
    private Keyring() {
        this(null);
    }

    /**
     * Constructor by specifying the SCrypt derived key for this keyring
     * @param derivedKey the SCrypt derived key for this keyring
     */
    private Keyring(byte[] derivedKey) {
        groupsById = new HashMap<>();
        this.derivedKey = derivedKey;
    }

    /**
     * Generates a new keyring with the specified passphrase to use for the SCrypt derived key.
     * The derived key will not be kept in memory
     * @param passphrase the passphrase of the keyring
     * @return the generated keyring
     */
    public static Keyring generateNew(String passphrase) {
        return generateNew(passphrase, false);
    }

    /**
     * Generates a new keyring with the specified passphrase to use for the SCrypt derived key,
     * and if the latter should be kept in memory or not
     * @param passphrase the passphrase of the keyring
     * @param stayUnlocked indicates if the derived key should be kept in memory or not
     * @return the generated keyring, or null if the given passphrase is null or empty
     */
    public static Keyring generateNew(String passphrase, boolean stayUnlocked) {
        if(passphrase == null || passphrase.trim().isEmpty())
            return null;

        EccEncryption ec = new EccEncryption();
        Scrypt scrypt = new Scrypt();

        byte[] derivedKey = scrypt.deriveKey(passphrase);
        AesCtrCipher encryptedPrivateKeyCipher = new AesCtrEncryption(derivedKey).encrypt(ec.getPrivateKeyBytes());

        Keyring keyring;
        if(stayUnlocked) {
            keyring = new Keyring(derivedKey);
        } else {
            keyring = new Keyring();
        }

        keyring.hexPublicKey = ec.encodePublicKey();
        keyring.hexEncryptedPrivateKey = encryptedPrivateKeyCipher.encodeDataBytes();
        keyring.hexIvPrivateKey = encryptedPrivateKeyCipher.encodeIv();
        keyring.hexScryptSalt = scrypt.encodeSalt();
        return keyring;
    }

    /**
     * Loads a keyring from a specified JSON file
     * @param file the file containing the JSON serialization of the keyring
     * @return the loaded keyring, or null if a problem occurred
     * @throws IOException if the file is not found nor accessible
     */
    public static Keyring loadFromFile(File file) throws IOException {
        try {
            return loadFromFile(file, null);
        } catch (PrivateKeyDecryptionException | BadPassphraseException e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Loads a keyring from a specified JSON file with its passphrase,
     * and keeps its derived key in memory
     * @param file the file containing the JSON serialization of the keyring
     * @param passphrase the passphrase of the corresponding keyring
     * @return the loaded keyring
     * @throws IOException if the file is not found/readable
     * @throws BadPassphraseException if the passphrase used is incorrect
     * @throws PrivateKeyDecryptionException if a problem occurred during the private key decryption
     */
    public static Keyring loadFromFile(File file, String passphrase) throws IOException, PrivateKeyDecryptionException, BadPassphraseException {
        BufferedReader br = new BufferedReader(new FileReader(file));
        String sJKeyring = br.readLine();
        br.close();

        JsonParser parser = new JsonParser();
        JsonObject jKeyRing = parser.parse(sJKeyring).getAsJsonObject();

        return fromJson(jKeyRing, passphrase);
    }

    /**
     * Saves the keyring into a JSON file
     * @param file the file to save the keyring into
     * @throws IOException if the file is not found/writable
     */
    public void saveToFile(File file) throws IOException {
        BufferedWriter bw = new BufferedWriter(new FileWriter(file));
        bw.write(this.toJson().toString());
        bw.close();
    }


    public byte[] sign(byte[] data, String passphrase) throws PrivateKeyDecryptionException, BadPassphraseException {
        byte[] privateKey = decryptECPrivateKey(retrieveDerivedKey(passphrase));
        EccEncryption ec = new EccEncryption(privateKey, HEX_ENCODER.decode(hexPublicKey));
        EccSignature signature = ec.sign(data);
        return signature.getBytes();
    }


    public static boolean verifySignature(byte[] signature, byte[] data, String hexPublicKey) {
        return EccEncryption.verifySignature(signature, data, HEX_ENCODER.decode(hexPublicKey));
    }


    public boolean verifySignature(byte[] signature, byte[] data) {
        if(this.hexPublicKey == null)
            return false;

        return verifySignature(signature, data, this.hexPublicKey);
    }


    public byte[] retrieveDerivedKey(String passphrase) {
        if(passphrase == null) {
            return this.derivedKey;
        } else {
            Scrypt scrypt = new Scrypt(hexScryptSalt);
            return scrypt.deriveKey(passphrase);
        }
    }

    /**
     * Adds a group to the keyring by specifying its id and its secret key
     * See {@link #addGroup(String, byte[])} if the keyring is already unlocked
     * @param passphrase the passphrase to unlock the keyring
     * @param groupId the id of the group to add
     * @param groupSecretKey the secret key of the group to add
     * @return true if the group was successfully added, false otherwise
     * @throws GroupIdException if the group id is incorrect (null or empty) or
     *                              if another group with the same id already
     *                              exists in the keyring
     * @throws BadPassphraseException if the passphrase used is incorrect
     * @throws PrivateKeyDecryptionException if a problem occurred during the private key decryption
     */
    public boolean addGroup(String passphrase, String groupId, byte[] groupSecretKey)
            throws GroupIdException, BadPassphraseException, PrivateKeyDecryptionException {

        Scrypt scrypt = new Scrypt(hexScryptSalt);
        return addGroup(scrypt.deriveKey(passphrase), groupId, groupSecretKey);
    }

    /**
     * Adds a group to the keyring by specifying its id and its secret key
     * See {@link #addGroup(String, String, byte[])}  if the keyring is not unlocked yet
     * @param groupId the id of the group to add
     * @param groupSecretKey the secret key of the group to add
     * @return true if the group was successfully added, false otherwise
     * @throws GroupIdException if the group id is incorrect (null or empty) or
     *                              if another group with the same id already
     *                              exists in the keyring
     * @throws BadPassphraseException if the passphrase used is incorrect
     * @throws PrivateKeyDecryptionException if a problem occurred during the private key decryption
     */
    public boolean addGroup(String groupId, byte[] groupSecretKey)
            throws GroupIdException, BadPassphraseException, PrivateKeyDecryptionException {
        return addGroup(this.derivedKey, groupId, groupSecretKey);
    }

    /**
     * Adds a group to the keyring by specifying its id and its secret key
     * See {@link #addGroup(String, byte[])} if the keyring is already unlocked
     * @param derivedKey the derived key for this keyring
     * @param groupId the id of the group to add
     * @param groupSecretKey the secret key of the group to add
     * @return true if the group was successfully added, false otherwise
     * @throws GroupIdException if the group id is incorrect (null or empty) or
     *                              if another group with the same id already
     *                              exists in the keyring
     * @throws BadPassphraseException if the derived key is incorrect for this keyring
     * @throws PrivateKeyDecryptionException if a problem occurred during the private key decryption
     */
    public boolean addGroup(byte[] derivedKey, String groupId, byte[] groupSecretKey)
            throws GroupIdException, PrivateKeyDecryptionException, BadPassphraseException {

        if(groupId == null || groupId.trim().isEmpty())
            throw new EmptyGroupIdException();

        if(groupsById.containsKey(groupId))
            throw new DuplicatedGroupIdException(groupId);

        AesCtrEncryption aes = initAESEncryption(derivedKey);
        AesCtrCipher groupKeyCipher = aes.encrypt(groupSecretKey);
        if(groupKeyCipher == null)
            return false;

        groupsById.put(groupId, new KeyringGroup(groupId, groupKeyCipher.encodeDataBytes(), groupKeyCipher.encodeIv()));
        return true;
    }

    /**
     * Retrieves the AES secret key of a given group.
     * See {@link #retrieveGroupKey(String)} if the keyring is already unlocked
     * @param passphrase the passphrase to unlock the keyring
     * @param groupId the id of the group to retrieve
     * @return the AES secret key bytes of the group
     * @throws GroupIdException if the group id is incorrect (null or empty) or
     *                              does not exist in the keyring
     * @throws BadPassphraseException if the passphrase is incorrect for this keyring
     * @throws PrivateKeyDecryptionException if a problem occurred during the private key decryption
     */
    public byte[] retrieveGroupKey(String passphrase, String groupId)
            throws GroupIdException, PrivateKeyDecryptionException, BadPassphraseException {

        Scrypt sCrypt = new Scrypt(hexScryptSalt);
        return retrieveGroupKey(sCrypt.deriveKey(passphrase), groupId);
    }

    /**
     * Retrieves the AES secret key of a given group.
     * See {@link #retrieveGroupKey(byte[], String)} if the keyring is not unlocked
     * @param groupId the id of the group to retrieve
     * @return the AES secret key bytes of the group
     * @throws GroupIdException if the group id is incorrect (null or empty) or
     *                              does not exist in the keyring
     * @throws BadPassphraseException if the derived key is incorrect for this keyring
     * @throws PrivateKeyDecryptionException if a problem occurred during the private key decryption
     */
    public byte[] retrieveGroupKey(String groupId)
            throws GroupIdException, PrivateKeyDecryptionException, BadPassphraseException {

        return retrieveGroupKey(this.derivedKey, groupId);
    }

    /**
     * Retrieves the AES secret key of a given group.
     * See {@link #retrieveGroupKey(byte[], String)} if the keyring is not unlocked
     * @param derivedKey the derived key for this keyring
     * @param groupId the id of the group to retrieve
     * @return the AES secret key bytes of the group
     * @throws GroupIdException if the group id is incorrect (null or empty) or
     *                              does not exist in the keyring
     * @throws BadPassphraseException if the derived key is incorrect for this keyring
     * @throws PrivateKeyDecryptionException if a problem occurred during the private key decryption
     */
    public byte[] retrieveGroupKey(byte[] derivedKey, String groupId)
            throws GroupIdException, PrivateKeyDecryptionException, BadPassphraseException {

        KeyringGroup group = groupsById.get(groupId);
        if(group == null)
            throw new NonExistingGroupIdException(groupId);

        byte[] encryptedSecretKey = HEX_ENCODER.decode(group.getHexEncryptedSecretKey());
        byte[] secretKeyIv = HEX_ENCODER.decode(group.getHexIvSecretKey());

        AesCtrEncryption aes = initAESEncryption(derivedKey);
        AesCtrCipher cipher = aes.decrypt(encryptedSecretKey, secretKeyIv);
        if(cipher == null)
            return null;

        return cipher.getDataBytes();
    }

    /**
     * Builds an {@link AesCtrEncryption} object that will use the EC private key
     * of the keyring as its AES secret key
     * @param derivedKey the key to decrypt the EC private key
     * @return the initiated {@link AesCtrEncryption} object
     * @throws BadPassphraseException if the derived key is incorrect for this keyring
     * @throws PrivateKeyDecryptionException if a problem occurred during the private key decryption
     */
    private AesCtrEncryption initAESEncryption(byte[] derivedKey)
            throws PrivateKeyDecryptionException, BadPassphraseException {
        if(derivedKey == null)
            throw new BadPassphraseException();

        byte[] ecPrivateKey = decryptECPrivateKey(derivedKey);
        SecretKey secretKey = AesCtrEncryption.toAESKey(ecPrivateKey);
        return new AesCtrEncryption(secretKey);
    }

    /**
     * Decrypts the EC private key of the keyring by using the SCrypt key derived from the passphrase
     * @param derivedKey the derived key to decrypt the EC private key with
     * @return the EC private key bytes
     * @throws BadPassphraseException if the derived key is incorrect for this keyring
     * @throws PrivateKeyDecryptionException if a problem occurred during the private key decryption
     */
    private byte[] decryptECPrivateKey(byte[] derivedKey)
            throws BadPassphraseException, PrivateKeyDecryptionException {

        byte[] encryptedPrivateKey = HEX_ENCODER.decode(hexEncryptedPrivateKey);
        byte[] privateKeyIv = HEX_ENCODER.decode(hexIvPrivateKey);
        AesCtrCipher ecPrivateKeyCipher = new AesCtrEncryption(derivedKey).decrypt(encryptedPrivateKey, privateKeyIv);
        if(ecPrivateKeyCipher == null)
            throw new PrivateKeyDecryptionException();

        byte[] privateKey = ecPrivateKeyCipher.getDataBytes();

        if(verifyPrivateKey(privateKey))
            return privateKey;
        else
            throw new BadPassphraseException();
    }

    /**
     * Verifies if the given private key is the right one for this keyring
     * @param ecPrivateKey the private key to test
     * @return true if the private key is correct, false otherwise
     */
    private boolean verifyPrivateKey(byte[] ecPrivateKey) {
        EccEncryption ec = new EccEncryption(ecPrivateKey, HEX_ENCODER.decode(hexPublicKey));
        EccSignature signature = ec.sign(HEX_ENCODER.decode(hexPublicKey));
        return ec.verifySignature(signature, HEX_ENCODER.decode(hexPublicKey));
    }

    /**
     * Verifies if the given passphrase is the correct one for this keyring
     * @param passphrase the passphrase to test
     * @return true if the passphrase is correct, false otherwise
     * @throws PrivateKeyDecryptionException if a problem occurred during the private key decryption
     */
    public boolean verifyPassphrase(String passphrase) throws PrivateKeyDecryptionException {
        Scrypt sCrypt = new Scrypt(hexScryptSalt);
        byte[] derivedKey = sCrypt.deriveKey(passphrase);
        return verifyDerivedKey(derivedKey);
    }

    /**
     * Verifies if the passphrase used beforehand to unlock the keyring is correct
     * @return true if the passphrase is correct, false otherwise
     * @throws PrivateKeyDecryptionException if a problem occurred during the private key decryption
     */
    public boolean verifyPassphrase() throws PrivateKeyDecryptionException {
        return verifyDerivedKey(derivedKey);
    }

    /**
     * Verifies if the given derived key is the correct one for this keyring's encrypted private key
     * @param derivedKey the derived key to test
     * @return true if the derived key is correct, false otherwise
     * @throws PrivateKeyDecryptionException if a problem occurred during the private key decryption
     */
    private boolean verifyDerivedKey(byte[] derivedKey) throws PrivateKeyDecryptionException {
        if(derivedKey == null)
            return false;

        byte[] encryptedPrivateKey = HEX_ENCODER.decode(hexEncryptedPrivateKey);
        byte[] privateKeyIv = HEX_ENCODER.decode(hexIvPrivateKey);
        AesCtrCipher ecPrivateKeyCipher = new AesCtrEncryption(derivedKey).decrypt(encryptedPrivateKey, privateKeyIv);
        if(ecPrivateKeyCipher == null)
            throw new PrivateKeyDecryptionException();

        return verifyPrivateKey(ecPrivateKeyCipher.getDataBytes());
    }

    /**
     * Serializes the current keyring to a JSON string
     * @return the JSON string representing the current keyring
     */
    public JsonObject toJson() {
        JsonObject jKeyring = new JsonObject();
        jKeyring.addProperty(JKEY_SCRYPT_SALT, hexScryptSalt);
        jKeyring.addProperty(JKEY_PUBLIC_KEY, hexPublicKey);

        JsonObject jPrivateKey = new JsonObject();
        jPrivateKey.addProperty(JKEY_CIPHER_TEXT, hexEncryptedPrivateKey);
        jPrivateKey.addProperty(JKEY_IV, hexIvPrivateKey);
        jKeyring.add(JKEY_PRIVATE_KEY, jPrivateKey);

        JsonArray jGroups = new JsonArray();
        for(KeyringGroup group : groupsById.values()) {
            JsonObject jGroup = new JsonObject();
            jGroup.addProperty(JKEY_GROUP_ID, group.getId());
            jGroup.addProperty(JKEY_CIPHER_TEXT, group.getHexEncryptedSecretKey());
            jGroup.addProperty(JKEY_IV, group.getHexIvSecretKey());

            jGroups.add(jGroup);
        }
        jKeyring.add(JKEY_GROUPS, jGroups);

        return jKeyring;
    }

    /**
     * Builds a keyring from a JSON representation
     * @param jKeyring the JSON string representing the keyring
     * @return the keyring built from the JSON string
     */
    public static Keyring fromJson(JsonObject jKeyring) {
        try {
            return fromJson(jKeyring, null);
        } catch (PrivateKeyDecryptionException | BadPassphraseException e) {
            e.printStackTrace();
            return null;
        }
    }

    /**
     * Builds a keyring from a JSON representation, and keeps the key derived from the
     * given passphrase in memory
     * @param jKeyring the JSON string representing the keyring
     * @param passphrase the passphrase to unlock the keyring
     * @return the keyring built from the JSON string
     */
    public static Keyring fromJson(JsonObject jKeyring, String passphrase) throws PrivateKeyDecryptionException, BadPassphraseException {
        Keyring keyring = new Keyring();
        keyring.hexScryptSalt = jKeyring.get(JKEY_SCRYPT_SALT).getAsString();
        keyring.hexPublicKey = jKeyring.get(JKEY_PUBLIC_KEY).getAsString();

        JsonObject jPrivateKey = jKeyring.getAsJsonObject(JKEY_PRIVATE_KEY);

        keyring.hexEncryptedPrivateKey = jPrivateKey.get(JKEY_CIPHER_TEXT).getAsString();
        keyring.hexIvPrivateKey = jPrivateKey.get(JKEY_IV).getAsString();

        JsonArray jGroups = jKeyring.getAsJsonArray(JKEY_GROUPS);
        for (JsonElement e : jGroups) {
            JsonObject jGroup = e.getAsJsonObject();
            KeyringGroup group = new KeyringGroup(
                    jGroup.get(JKEY_GROUP_ID).getAsString(),
                    jGroup.get(JKEY_CIPHER_TEXT).getAsString(),
                    jGroup.get(JKEY_IV).getAsString()
            );
            keyring.groupsById.put(group.getId(), group);
        }

        if(passphrase != null) {
            Scrypt scrypt   = new Scrypt(keyring.hexScryptSalt);
            keyring.derivedKey = scrypt.deriveKey(passphrase);

            if(!keyring.verifyPassphrase()) {
                throw new BadPassphraseException();
            }
        }
        return keyring;
    }

    /**
     * Returns the list of the ids of all the groups inside the current keyring
     * @return the list of the ids of all the groups inside the current keyring
     */
    public List<String> getGroupIds() {
        return new ArrayList<>(groupsById.keySet());
    }

    public String getHexPublicKey() {
        return hexPublicKey;
    }
}
