package testcode.taint.distrustderived;

public class DistrustCommand {

    private String command;

    public String command() {
        return "pwd";
    }

    public void append(StringBuilder sb) {
        sb.append(command);
    }
}
