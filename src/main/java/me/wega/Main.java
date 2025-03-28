package me.wega;

import java.util.HexFormat;

public class Main {
    public static void main(String[] args) {
        chaCha20();
    }

    public static void chaCha20() {
        final byte[] keyBytes = HexFormat.of().parseHex(
                "00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f"
                        .replace(":", "")
        );
        final byte[] ivBytes = HexFormat.of().parseHex(
                "00:00:00:00:00:00:00:4a:00:00:00:00"
                        .replace(":", "")
        );
        int initialCounter = 1;

        final byte[] plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
                .getBytes();

        final byte[] encrypted = ChaCha20.encrypt(keyBytes, initialCounter, ivBytes, plaintext);
        System.out.println("ENCRYPTED = " + HexFormat.of().formatHex(encrypted));

        final byte[] decrypted = ChaCha20.encrypt(keyBytes, initialCounter, ivBytes, encrypted);
        System.out.println("DECRYPTED = " + new String(decrypted));
    }
}