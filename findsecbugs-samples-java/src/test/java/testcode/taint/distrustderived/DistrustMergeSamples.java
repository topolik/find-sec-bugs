package testcode.taint.distrustderived;

import java.io.IOException;

public class DistrustMergeSamples {

    public static String defaultCommand() {
        return "pwd";
    }

    public DistrustSafeBase createSafe() {
        return new DistrustSafeOverrider();
    }

    public DistrustBase create() {
        return new DistrustOverrider();
    }

    public void mergedCommand(DistrustSafeBase base) throws IOException {
        Runtime.getRuntime().exec(base.command());
    }

    public void mergedAppendCommand(DistrustSafeBase base) throws IOException {
        StringBuilder sb = new StringBuilder();
        base.append(sb);
        Runtime.getRuntime().exec(sb.toString());
    }

    public void mergedUnknownCommand(DistrustBase base) throws IOException {
        Runtime.getRuntime().exec(base.command());
    }

    public void pendingCommand(DistrustPendingBase base) throws IOException {
        Runtime.getRuntime().exec(base.command());
    }
}
