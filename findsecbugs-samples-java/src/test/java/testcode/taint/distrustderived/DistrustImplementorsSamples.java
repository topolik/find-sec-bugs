package testcode.taint.distrustderived;

import java.io.IOException;

public class DistrustImplementorsSamples {

    public DistrustSource createSource() {
        return new DistrustSourceImpl();
    }

    public DistrustSource createCommandSource() {
        return new DistrustCommandSource();
    }

    public DistrustFunctionalSource createFunctionalSource() {
        return new DistrustFunctionalSourceImpl();
    }

    public DistrustAbstractSource createDefaultSource() {
        return new DistrustDefaultSourceImpl();
    }

    public void implementorsCommand(DistrustSource source) throws IOException {
        Runtime.getRuntime().exec(source.command());
    }

    public void implementorsAppendCommand(DistrustSource source) throws IOException {
        StringBuilder sb = new StringBuilder();
        source.append(sb);
        Runtime.getRuntime().exec(sb.toString());
    }

    public void abstractCommand(DistrustAbstractSource source) throws IOException {
        Runtime.getRuntime().exec(source.command());
    }

    public void functionalCommand(DistrustFunctionalSource source) throws IOException {
        Runtime.getRuntime().exec(source.command());
    }

    public void equalsCommand(DistrustEqualsSource source) throws IOException {
        Runtime.getRuntime().exec(source.command());
    }
}
