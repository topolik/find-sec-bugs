package testcode.taint.distrustderived;

public interface DistrustDefaultSource extends DistrustFunctionalSource {

    @Override
    default String command() {
        return "ls";
    }
}
