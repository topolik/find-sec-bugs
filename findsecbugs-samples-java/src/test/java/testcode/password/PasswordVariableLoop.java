package testcode.password;

public abstract class PasswordVariableLoop {

    public boolean check(byte[] input, byte[] password, String... passwordContexts) {
        for (String passwordContext : passwordContexts) {
            Object passwordProvider = getPasswordProvider(passwordContext);

            input = generate(passwordProvider, input);
        }

        return java.security.MessageDigest.isEqual(input, password);
    }

    public abstract Object getPasswordProvider(String name);

    public abstract byte[] generate(Object passwordProvider, byte[] input);

}
