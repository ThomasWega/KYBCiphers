package me.wega;

public class ChaCha20 {
    public static byte[] encrypt(byte[] key, int counter, byte[] nonce, byte[] plaintext) {
        byte[] encryptedMessage = new byte[plaintext.length];
        int fullBlocks = plaintext.length / 64;

        for (int j = 0; j < fullBlocks; j++) {
            byte[] keyStream = generateBlock(key, counter + j, nonce);
            byte[] block = new byte[64];
            System.arraycopy(plaintext, j * 64, block, 0, 64);

            for (int i = 0; i < 64; i++) {
                encryptedMessage[j * 64 + i] = (byte) (block[i] ^ keyStream[i]);
            }
        }

        int remainingBytes = plaintext.length % 64;
        if (remainingBytes != 0) {
            int j = plaintext.length / 64;
            byte[] keyStream = generateBlock(key, counter + j, nonce);
            byte[] block = new byte[remainingBytes];
            System.arraycopy(plaintext, j * 64, block, 0, remainingBytes);

            for (int i = 0; i < remainingBytes; i++) {
                encryptedMessage[j * 64 + i] = (byte) (block[i] ^ keyStream[i]);
            }
        }

        return encryptedMessage;
    }

    private static void innerBlock(int[] state) {
        quarterRound(state, 0, 4, 8, 12);
        quarterRound(state, 1, 5, 9, 13);
        quarterRound(state, 2, 6, 10, 14);
        quarterRound(state, 3, 7, 11, 15);
        quarterRound(state, 0, 5, 10, 15);
        quarterRound(state, 1, 6, 11, 12);
        quarterRound(state, 2, 7, 8, 13);
        quarterRound(state, 3, 4, 9, 14);
    }

    private static byte[] generateBlock(byte[] key, int counter, byte[] nonce) {
        int[] state = new int[16];
        state[0] = 0x61707865;
        state[1] = 0x3320646e;
        state[2] = 0x79622d32;
        state[3] = 0x6b206574;

        for (int i = 0; i < 8; i++) {
            state[4 + i] = littleEndianToInt(key, i * 4);
        }

        state[12] = counter;

        for (int i = 0; i < 3; i++) {
            state[13 + i] = littleEndianToInt(nonce, i * 4);
        }

        int[] workingState = state.clone();

        for (int i = 0; i < 10; i++) {
            innerBlock(workingState);
        }

        for (int i = 0; i < 16; i++) {
            state[i] += workingState[i];
        }

        return serialize(state);
    }

    private static int littleEndianToInt(byte[] bytes, int offset) {
        return (bytes[offset] & 0xFF) |
                ((bytes[offset + 1] & 0xFF) << 8) |
                ((bytes[offset + 2] & 0xFF) << 16) |
                ((bytes[offset + 3] & 0xFF) << 24);
    }

    private static byte[] serialize(int[] state) {
        byte[] output = new byte[64];
        for (int i = 0; i < 16; i++) {
            output[i * 4] = (byte) (state[i] & 0xFF);
            output[i * 4 + 1] = (byte) ((state[i] >>> 8) & 0xFF);
            output[i * 4 + 2] = (byte) ((state[i] >>> 16) & 0xFF);
            output[i * 4 + 3] = (byte) ((state[i] >>> 24) & 0xFF);
        }
        return output;
    }

    private static final int OVER = 0xffffffff;

    private static void quarterRound(int[] state, int ai, int bi, int ci, int di) {
        int a = state[ai];
        int b = state[bi];
        int c = state[ci];
        int d = state[di];

        // a += b; d ^= a; d <<<= 16;
        a = (a + b) & OVER;
        d = d ^ a;
        d = rotateLeft(d, 16);

        // c += d; b ^= c; b <<<= 12;
        c = (c + d) & OVER;
        b = b ^ c;
        b = rotateLeft(b, 12);

        // a += b; d ^= a; d <<<= 8;
        a = (a + b) & OVER;
        d = d ^ a;
        d = rotateLeft(d, 8);

        // c += d; b ^= c; b <<<= 7;
        c = (c + d) & OVER;
        b = b ^ c;
        b = rotateLeft(b, 7);

        state[ai] = a;
        state[bi] = b;
        state[ci] = c;
        state[di] = d;
    }

    private static int rotateLeft(int value, int offset) {
        return ((value << offset) | (value >>> (32 - offset))) & OVER;
    }
}
