package testcode.taint.distrustderived;

import java.io.IOException;

public class DistrustSamples {

    public void overriddenCommand(DistrustBase base) throws IOException {
        Runtime.getRuntime().exec(base.command());
    }

    public void defaultCommand(DistrustDefault command) throws IOException {
        Runtime.getRuntime().exec(command.command());
    }

    public void finalCommand(DistrustBase base) throws IOException {
        Runtime.getRuntime().exec(base.finalCommand());
    }

    public void leafCommand(DistrustLeaf leaf) throws IOException {
        Runtime.getRuntime().exec(leaf.command());
    }

    public void constructedCommand(String input) throws IOException {
        Runtime.getRuntime().exec(String.valueOf(new DistrustHolder(input)));
    }
}
