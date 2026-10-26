package testcode.taint.distrustderived;

public class DistrustSafeBase {

    public String command() {
        return "ls";
    }

    public void append(StringBuilder sb) {
        sb.append("ls");
    }
}
