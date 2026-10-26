package testcode.taint.distrustderived;

public class DistrustPendingOverrider extends DistrustPendingBase {

    @Override
    public String command() {
        return DistrustMergeSamples.defaultCommand();
    }
}
