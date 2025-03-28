package me.wega;

import java.util.Arrays;

public class ChaCha20 {
    private final int[] state;
    private static final int[] CONSTANTS = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};
    private static final int MOD_MASK = 0xffffffff;


    public ChaCha20(byte[] key, byte[] iv, int initialCounter) {
        state = new int[16];
        int[] keySetup = prepareKey(key);
        int[] nonceSetup = prepareNonce(iv);


        System.arraycopy(CONSTANTS, 0, state, 0, 4);
        System.arraycopy(keySetup, 0, state, 4, 8);
        state[12] = initialCounter;
        System.arraycopy(nonceSetup, 0, state, 13, 3);
    }


    private int[] prepareKey(byte[] key) {
        int[] keyInts = convertBytesToInts(key, 256 / 32);
        reverseIntArray(keyInts);
        return keyInts;
    }


    private int[] prepareNonce(byte[] iv) {
        int[] nonceInts = convertBytesToInts(iv, 96 / 32);
        reverseIntArray(nonceInts);
        return nonceInts;
    }


    private int[] convertBytesToInts(byte[] bytes, int intCount) {
        int[] ints = new int[intCount];
        for (int i = 0; i < intCount; i++) {
            ints[i] = littleEndianBytesToInt(bytes, i * 4);
        }
        return ints;
    }


    private int littleEndianBytesToInt(byte[] bytes, int offset) {
        return (bytes[offset] & 0xFF) |
                ((bytes[offset + 1] & 0xFF) << 8) |
                ((bytes[offset + 2] & 0xFF) << 16) |
                ((bytes[offset + 3] & 0xFF) << 24);
    }


    private void reverseIntArray(int[] arr) {
        for (int i = 0; i < arr.length / 2; i++) {
            int temp = arr[i];
            arr[i] = arr[arr.length - 1 - i];
            arr[arr.length - 1 - i] = temp;
        }
    }


    private int rotateLeft(int value, int shift) {
        return ((value << shift) & MOD_MASK) | (value >>> (32 - shift));
    }


    private void quarterRound(int[] x, int a, int b, int c, int d) {
        x[a] = (x[a] + x[b]) & MOD_MASK;
        x[d] = rotateLeft(x[d] ^ x[a], 16);
        x[c] = (x[c] + x[d]) & MOD_MASK;
        x[b] = rotateLeft(x[b] ^ x[c], 12);
        x[a] = (x[a] + x[b]) & MOD_MASK;
        x[d] = rotateLeft(x[d] ^ x[a], 8);
        x[c] = (x[c] + x[d]) & MOD_MASK;
        x[b] = rotateLeft(x[b] ^ x[c], 7);
    }


    private void doubleRound(int[] x) {
        quarterRound(x, 0, 4, 8, 12);
        quarterRound(x, 1, 5, 9, 13);
        quarterRound(x, 2, 6, 10, 14);
        quarterRound(x, 3, 7, 11, 15);
        quarterRound(x, 0, 5, 10, 15);
        quarterRound(x, 1, 6, 11, 12);
        quarterRound(x, 2, 7, 8, 13);
        quarterRound(x, 3, 4, 9, 14);
    }


    private byte[] generateKeystream(int counter) {
        int[] initialState = Arrays.copyOf(state, state.length);
        state[12] = counter;
        int[] workingState = Arrays.copyOf(state, state.length);


        for (int i = 0; i < 10; i++) {
            doubleRound(workingState);
        }


        for (int i = 0; i < 16; i++) {
            workingState[i] = (workingState[i] + initialState[i]) & MOD_MASK;
        }


        byte[] keyStream = new byte[64];
        for (int i = 0; i < 16; i++) {
            intToLittleEndian(workingState[i], keyStream, i * 4);
        }
        state[12] = initialState[12]; // Restore original counter
        return keyStream;
    }


    private void intToLittleEndian(int value, byte[] bytes, int offset) {
        bytes[offset] = (byte) (value & 0xFF);
        bytes[offset + 1] = (byte) ((value >>> 8) & 0xFF);
        bytes[offset + 2] = (byte) ((value >>> 16) & 0xFF);
        bytes[offset + 3] = (byte) ((value >>> 24) & 0xFF);
    }


    public byte[] xor(byte[] data) {
        int dataLength = data.length;
        byte[] output = new byte[dataLength];
        int numBlocks = dataLength / 64;


        for (int i = 0; i < numBlocks; i++) {
            byte[] keyStream = generateKeystream(state[12] + i);
            for (int j = 0; j < 64; j++) {
                output[i * 64 + j] = (byte) (data[i * 64 + j] ^ keyStream[j]);
            }
        }


        if (dataLength % 64 != 0) {
            byte[] keyStream = generateKeystream(state[12] + numBlocks);
            int remainingBytes = dataLength % 64;
            for (int j = 0; j < remainingBytes; j++) {
                output[numBlocks * 64 + j] = (byte) (data[numBlocks * 64 + j] ^ keyStream[j]);
            }
        }
        return output;
    }
}
