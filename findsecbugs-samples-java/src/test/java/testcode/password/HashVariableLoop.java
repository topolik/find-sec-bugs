package testcode.password;

public abstract class HashVariableLoop {

    public boolean verify(byte[] input, byte[] hash, String... hashContexts) {
        for (String hashContext : hashContexts) {
            Object hashProvider = getHashProvider(hashContext);

            input = generate(hashProvider, input);
        }

        return java.security.MessageDigest.isEqual(input, hash);
    }

    public abstract Object getHashProvider(String name);

    public abstract byte[] generate(Object hashProvider, byte[] input);

}
