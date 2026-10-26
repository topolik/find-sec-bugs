package testcode.taint.distrustderived;

public interface DistrustSource {

    String command();

    void append(StringBuilder sb);
}
