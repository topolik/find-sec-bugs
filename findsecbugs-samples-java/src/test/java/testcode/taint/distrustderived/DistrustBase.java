package testcode.taint.distrustderived;

public class DistrustBase {

    public String command() {
        return "ls";
    }

    public final String finalCommand() {
        return "ls";
    }
}
