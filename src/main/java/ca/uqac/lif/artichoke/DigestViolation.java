package ca.uqac.lif.artichoke;

public class DigestViolation {

    private int position;
    private PeerAction peerAction;

    public DigestViolation(int position, PeerAction peerAction) {
        this.position = position;
        this.peerAction = peerAction;
    }


    @Override
    public String toString() {
        return String.format(
                "Peer-action at positon %d: invalid digest for %s",
                position,
                peerAction.toString());
    }

    public int getPosition() {
        return position;
    }

    public PeerAction getPeerAction() {
        return peerAction;
    }
}
