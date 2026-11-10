package testcode.taint.distrustderived;

public class DistrustFunctionalSourceImpl implements DistrustFunctionalSource, DistrustEqualsSource {

    @Override
    public String command() {
        return "ls";
    }
}
