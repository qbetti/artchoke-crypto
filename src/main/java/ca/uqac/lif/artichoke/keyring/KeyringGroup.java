package ca.uqac.lif.artichoke.keyring;

public class KeyringGroup {

    private String id;
    private String hexEncryptedSecretKey;
    private String hexIvSecretKey;

    public KeyringGroup(String id, String hexEncryptedSecretKey, String hexIvSecretKey) {
        this.id = id;
        this.hexEncryptedSecretKey = hexEncryptedSecretKey;
        this.hexIvSecretKey = hexIvSecretKey;
    }


    public String getId() {
        return id;
    }

    public String getHexEncryptedSecretKey() {
        return hexEncryptedSecretKey;
    }

    public String getHexIvSecretKey() {
        return hexIvSecretKey;
    }
}
