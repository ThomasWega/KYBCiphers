package me.wega;

public class Main {
    public static void main(String[] args) {
        chaCha20();
    }

    public static void chaCha20() {
        String key = "ThisIsAKeyForChaCha20CipherUwu11"; // Must be exactly 32 bytes
        byte[] keyBytes = key.getBytes();
        // (nonce) - must be 12 bytes
        String iv = "9B0PMrNzh7k=";
        byte[] ivBytes = iv.getBytes();
        int initialCounter = 1;

        ChaCha20 chacha = new ChaCha20(keyBytes, ivBytes, initialCounter);
        byte[] plaintext = "Hello World.".getBytes();
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