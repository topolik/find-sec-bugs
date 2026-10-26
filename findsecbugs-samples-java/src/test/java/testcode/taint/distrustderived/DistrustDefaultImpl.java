package testcode.taint.distrustderived;

public class DistrustDefaultImpl implements DistrustDefault {

    private String command;

    @Override
    public String command() {
        return command;
    }
}
