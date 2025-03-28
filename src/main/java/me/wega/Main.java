package me.wega;

import java.util.HexFormat;

public class Main {
    public static void main(String[] args) {
        chaCha20();
    }

    public static void chaCha20() {
        byte[] keyBytes = HexFormat.of().parseHex(
                "00:01:02:03:04:05:06:07:08:09:0a:0b:0c:0d:0e:0f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f"
                        .replace(":", "")
        );
        byte[] ivBytes = HexFormat.of().parseHex(
                "00:00:00:00:00:00:00:4a:00:00:00:00"
                        .replace(":", "")
        );
        int initialCounter = 1;

        ChaCha20 chacha = new ChaCha20(keyBytes, ivBytes, initialCounter);
        byte[] plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
                .getBytes();
        byte[] ciphertext = chacha.xor(plaintext);
        System.out.println("Encrypted: " + bytesToHex(ciphertext));


        ChaCha20 chacha2 = new ChaCha20(keyBytes, ivBytes, initialCounter);
        byte[] decrypted = chacha2.xor(ciphertext);
        System.out.println("Decrypted: " + new String(decrypted));
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }

}