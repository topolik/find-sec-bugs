package testcode.password;

public class MagicNumberSignature {

    private static final byte[] PNG_SIGNATURE = {-119, 80, 78, 71, 13, 10, 26, 10};

    public static boolean isPNG(byte[] bytes) {
        return java.util.Arrays.equals(PNG_SIGNATURE, bytes);
    }
}
