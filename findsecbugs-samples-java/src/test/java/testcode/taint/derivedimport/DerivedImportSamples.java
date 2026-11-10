package testcode.taint.derivedimport;

import java.io.IOException;

public class DerivedImportSamples {

    public void fillCommand() throws IOException {
        StringBuilder sb = new StringBuilder("ls ");
        DerivedImportHelper.fill(sb);
        Runtime.getRuntime().exec(sb.toString());
    }

    public void touchCommand(boolean flag, String suffix) throws IOException {
        String command = "ls ";
        if (flag) {
            DerivedImportHelper.touch(command);
        }
        Runtime.getRuntime().exec(command + suffix);
    }

    public void sourceCommand(DerivedImportSource source) throws IOException {
        Runtime.getRuntime().exec(source.get());
    }
}
