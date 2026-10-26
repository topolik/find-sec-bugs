package testcode.taint.derivedimport;

import java.io.IOException;

public class DerivedImportSamples {

    public void fillCommand() throws IOException {
        StringBuilder sb = new StringBuilder("ls ");
        DerivedImportHelper.fill(sb);
        Runtime.getRuntime().exec(sb.toString());
    }

    public void sourceCommand(DerivedImportSource source) throws IOException {
        Runtime.getRuntime().exec(source.get());
    }
}
