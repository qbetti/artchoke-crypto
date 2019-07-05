package ca.uqac.lif.artichoke.exceptions;

public class ScryptKeyDerivationException extends Exception {

    private static final String DEFAULT_MSG = "An error occurred during key derivation with the specified passphrase";

    public ScryptKeyDerivationException() {
        super(DEFAULT_MSG);
    }

}
