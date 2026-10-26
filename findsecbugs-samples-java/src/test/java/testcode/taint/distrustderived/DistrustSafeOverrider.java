package testcode.taint.distrustderived;

public class DistrustSafeOverrider extends DistrustSafeBase {

    @Override
    public String command() {
        return "pwd";
    }

    @Override
    public void append(StringBuilder sb) {
        sb.append("pwd");
    }
}
