package testcode.taint.distrustderived;

public class DistrustSourceImpl implements DistrustSource {

    @Override
    public String command() {
        return "ls";
    }

    @Override
    public void append(StringBuilder sb) {
        sb.append("ls");
    }
}
