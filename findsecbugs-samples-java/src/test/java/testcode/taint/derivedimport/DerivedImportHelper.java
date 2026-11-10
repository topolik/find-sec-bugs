package testcode.taint.derivedimport;

public class DerivedImportHelper {

    public static void fill(StringBuilder sb) {
        sb.append("-la");
    }

    public static void touch(String value) {
        value.length();
    }
}
