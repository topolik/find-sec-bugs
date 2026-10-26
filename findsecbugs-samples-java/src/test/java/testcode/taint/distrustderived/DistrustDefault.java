package testcode.taint.distrustderived;

public interface DistrustDefault {

    default String command() {
        return "ls";
    }
}
