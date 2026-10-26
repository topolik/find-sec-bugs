package testcode.taint.distrustderived;

public class DistrustOverrider extends DistrustBase {

    private String command;

    @Override
    public String command() {
        return command;
    }
}
