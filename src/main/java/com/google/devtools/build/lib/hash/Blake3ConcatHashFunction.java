// Copyright 2022 The Bazel Authors. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//    http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package com.google.devtools.build.lib.hash;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.base.Preconditions.checkPositionIndexes;

import com.google.common.hash.Funnel;
import com.google.common.hash.HashCode;
import com.google.common.hash.HashFunction;
import com.google.common.hash.Hasher;
import com.google.errorprone.annotations.Immutable;
import java.lang.UnsupportedOperationException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.Charset;
import java.util.Arrays;

@Immutable
public final class Blake3ConcatHashFunction implements HashFunction {
  /* BEGINNING OF STUFF COPIED FROM AbstractHashFunction! */
  @Override
  public <T extends Object> HashCode hashObject(
      T instance, Funnel<? super T> funnel) {
    return newHasher().putObject(instance, funnel).hash();
  }

  @Override
  public HashCode hashUnencodedChars(CharSequence input) {
    int len = input.length();
    return newHasher(len * 2).putUnencodedChars(input).hash();
  }

  @Override
  public HashCode hashString(CharSequence input, Charset charset) {
    return newHasher().putString(input, charset).hash();
  }

  @Override
  public HashCode hashInt(int input) {
    return newHasher(4).putInt(input).hash();
  }

  @Override
  public HashCode hashLong(long input) {
    return newHasher(8).putLong(input).hash();
  }

  @Override
  public HashCode hashBytes(byte[] input) {
    return hashBytes(input, 0, input.length);
  }

  @Override
  public HashCode hashBytes(byte[] input, int off, int len) {
    checkPositionIndexes(off, off + len, input.length);
    return newHasher(len).putBytes(input, off, len).hash();
  }

  @Override
  public HashCode hashBytes(ByteBuffer input) {
    return newHasher(input.remaining()).putBytes(input).hash();
  }

  @Override
  public Hasher newHasher(int expectedInputSize) {
    checkArgument(
        expectedInputSize >= 0, "expectedInputSize must be >= 0 but was %s", expectedInputSize);
    return newHasher();
  }
  /* END OF STUFF COPIED FROM AbstractHashFunction! */

  @Override
  public int bits() {
    return 256;
  }

  @Override
  public Hasher newHasher() {
    return new Blake3concatHasher();
  }

  private final static class Blake3concatHasher implements Hasher {
    /* BEGINNING OF STUFF COPIED FROM AbstractHasher! */
    @Override
    public final Hasher putBoolean(boolean b) {
      return putByte(b ? (byte) 1 : (byte) 0);
    }

    @Override
    public final Hasher putDouble(double d) {
      return putLong(Double.doubleToRawLongBits(d));
    }

    @Override
    public final Hasher putFloat(float f) {
      return putInt(Float.floatToRawIntBits(f));
    }

    @Override
    public Hasher putUnencodedChars(CharSequence charSequence) {
      for (int i = 0, len = charSequence.length(); i < len; i++) {
        putChar(charSequence.charAt(i));
      }
      return this;
    }

    @Override
    public Hasher putString(CharSequence charSequence, Charset charset) {
      return putBytes(charSequence.toString().getBytes(charset));
    }

    @Override
    public Hasher putBytes(byte[] bytes) {
      return putBytes(bytes, 0, bytes.length);
    }

    @Override
    public Hasher putBytes(byte[] bytes, int off, int len) {
      checkPositionIndexes(off, off + len, bytes.length);
      update(bytes, off, len);
      return this;
    }

    @Override
    public Hasher putBytes(ByteBuffer b) {
      if (b.hasArray()) {
        putBytes(b.array(), b.arrayOffset() + b.position(), b.remaining());
        b.position(b.limit());
      } else {
        for (int remaining = b.remaining(); remaining > 0; remaining--) {
          putByte(b.get());
        }
      }
      return this;
    }

    @Override
    public Hasher putShort(short s) {
      putByte((byte) s);
      putByte((byte) (s >>> 8));
      return this;
    }

    @Override
    public Hasher putInt(int i) {
      putByte((byte) i);
      putByte((byte) (i >>> 8));
      putByte((byte) (i >>> 16));
      putByte((byte) (i >>> 24));
      return this;
    }

    @Override
    public Hasher putLong(long l) {
      for (int i = 0; i < 64; i += 8) {
        putByte((byte) (l >>> i));
      }
      return this;
    }

    @Override
    public Hasher putChar(char c) {
      putByte((byte) c);
      putByte((byte) (c >>> 8));
      return this;
    }

    @Override
    public <T extends Object> Hasher putObject(
        T instance, Funnel<? super T> funnel) {
      funnel.funnel(instance, this);
      return this;
    }
    /* END OF STUFF COPIED FROM AbstractHasher! */

    @Override
    public Hasher putByte(byte b) {
      update(new byte[]{b});
      return this;
    }

    @Override
    public HashCode hash() {
        Node node = this.chunkState.createNode();
        int parentNodesRemaining = cvStackLen;
        while(parentNodesRemaining > 0){
            parentNodesRemaining -=1;
            node = parentNode(
                    cvStack[parentNodesRemaining],
                    node.chainingValue(),
                    key,
                    flags
            );
        }
        return HashCode.fromBytes(node.rootOutputBytes());
    }


    // XXX

    private static final char[] HEX_ARRAY = "0123456789abcdef".toCharArray();

    private static final int OUT_LEN = 32;
    private static final int KEY_LEN = 32;
    private static final int BLOCK_LEN = 64;
    private static final int CHUNK_LEN = 1024;

    private static final int CHUNK_START = 1;
    private static final int CHUNK_END = 2;
    private static final int PARENT = 4;
    private static final int KEYED_HASH = 16;
    private static final int DERIVE_KEY_CONTEXT = 32;
    private static final int DERIVE_KEY_MATERIAL = 64;

    private static final int[] IV = {
            0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A, 0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19
    };

    private static final int[] MSG_PERMUTATION = {
            2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8
    };

    private static int wrappingAdd(int a, int b){
        return (a + b);
    }

    private static int rotateRight(int x, int len){
        return (x >>> len) | (x << (32 - len));
    }

    private static void g(int[] state, int a, int b, int c, int d, int mx, int my){
        state[a] = wrappingAdd(wrappingAdd(state[a], state[b]), mx);
        state[d] = rotateRight((state[d] ^ state[a]), 16);
        state[c] = wrappingAdd(state[c], state[d]);
        state[b] = rotateRight((state[b] ^ state[c]), 12);
        state[a] = wrappingAdd(wrappingAdd(state[a], state[b]), my);
        state[d] = rotateRight((state[d] ^ state[a]), 8);
        state[c] = wrappingAdd(state[c], state[d]);
        state[b] = rotateRight((state[b] ^ state[c]), 7);
    }

    private static void roundFn(int[] state, int[] m){
        // Mix columns
        g(state,0,4,8,12,m[0],m[1]);
        g(state,1,5,9,13,m[2],m[3]);
        g(state,2,6,10,14,m[4],m[5]);
        g(state,3,7,11,15,m[6],m[7]);

        // Mix diagonals
        g(state,0,5,10,15,m[8],m[9]);
        g(state,1,6,11,12,m[10],m[11]);
        g(state,2,7,8,13,m[12],m[13]);
        g(state,3,4,9,14,m[14],m[15]);
    }

    private static int[] permute(int[] m){
        int[] permuted = new int[16];
        for(int i = 0;i<16;i++){
            permuted[i] = m[MSG_PERMUTATION[i]];
        }
        return permuted;
    }

    private static int[] compress(int[] chainingValue, int[] blockWords, int blockLen, int flags){
        int[] state = {
                chainingValue[0],
                chainingValue[1],
                chainingValue[2],
                chainingValue[3],
                chainingValue[4],
                chainingValue[5],
                chainingValue[6],
                chainingValue[7],
                IV[0],
                IV[1],
                IV[2],
                IV[3],
                0,
                0,
                blockLen,
                flags
        };
        roundFn(state, blockWords);         // Round 1
        blockWords = permute(blockWords);
        roundFn(state, blockWords);         // Round 2
        blockWords = permute(blockWords);
        roundFn(state, blockWords);         // Round 3
        blockWords = permute(blockWords);
        roundFn(state, blockWords);         // Round 4
        blockWords = permute(blockWords);
        roundFn(state, blockWords);         // Round 5
        blockWords = permute(blockWords);
        roundFn(state, blockWords);         // Round 6
        blockWords = permute(blockWords);
        roundFn(state, blockWords);         // Round 7

        for(int i = 0; i<8; i++){
            state[i] ^= state[i+8];
            state[i+8] ^= chainingValue[i];
        }
        return Arrays.copyOfRange(state, 0, 8);
    }

    private static int[] wordsFromLEBytes(byte[] bytes){
        int[] words = new int[bytes.length/4];
        ByteBuffer buf = ByteBuffer.wrap(bytes).order(ByteOrder.LITTLE_ENDIAN);

        for(int i=0; i<words.length; i++){
            words[i] = buf.getInt();
        }
        return words;
    }

    // Node of the Blake3 hash tree
    // Is either chained into the next node using chainingValue()
    // Or used to calculate the hash digest using rootOutputBytes()
    private static class Node {
        int[] inputChainingValue;
        int[] blockWords;
        int blockLen;
        int flags;

        private Node(int[] inputChainingValue, int[] blockWords, int blockLen, int flags) {
            this.inputChainingValue = inputChainingValue;
            this.blockWords = blockWords;
            this.blockLen = blockLen;
            this.flags = flags;
        }

        // Return the 8 int CV
        private int[] chainingValue(){
            return Arrays.copyOfRange(
                    compress(inputChainingValue, blockWords, blockLen, flags),
                    0,8);
        }

        private byte[] rootOutputBytes() {
            byte[] hash = new byte[32];
            int i = 0;
            int[] words = compress(inputChainingValue, blockWords, blockLen, flags);

            for(int word : words){
                for(byte b: ByteBuffer.allocate(4)
                        .order(ByteOrder.LITTLE_ENDIAN)
                        .putInt(word)
                        .array()){
                    hash[i] = b;
                    i+=1;
                }
            }
            return hash;
        }
    }

    // Helper object for creating new Nodes and chaining them
    private static class ChunkState {
        int[] chainingValue;
        long chunkCounter;
        byte[] block = new byte[BLOCK_LEN];
        byte blockLen = 0;
        byte blocksCompressed = 0;
        int flags;

        public ChunkState(int[] key, long chunkCounter, int flags){
            this.chainingValue = key;
            this.chunkCounter = chunkCounter;
            this.flags = flags;
        }

        public int len(){
            return BLOCK_LEN * blocksCompressed + blockLen;
        }

        private int startFlag(){
            return blocksCompressed == 0? CHUNK_START: 0;
        }

        private void update(byte[] input, int offset, int length) {
            int currPos = offset;
            while (currPos < length + offset) {

                // Chain the next 64 byte block into this chunk/node
                if (blockLen == BLOCK_LEN) {
                    int[] blockWords = wordsFromLEBytes(block);
                    this.chainingValue = compress(this.chainingValue, blockWords, BLOCK_LEN,this.flags | this.startFlag());
                    blocksCompressed += 1;
                    this.block = new byte[BLOCK_LEN];
                    this.blockLen = 0;
                }

                // Take bytes out of the input and update
                int want = BLOCK_LEN - this.blockLen; // How many bytes we need to fill up the current block
                int canTake = Math.min(want, input.length - currPos);

                System.arraycopy(input, currPos, block, blockLen, canTake);
                blockLen += canTake;
                currPos+=canTake;
            }
        }

        private Node createNode(){
            return new Node(chainingValue, wordsFromLEBytes(block), blockLen, flags | startFlag() | CHUNK_END);
        }
    }

    // Hasher
    private ChunkState chunkState;
    private int[] key;
    private final int[][] cvStack = new int[54][];
    private byte cvStackLen = 0;
    private int flags;

    private Blake3concatHasher(){
        initialize(IV,0);
    }

    private Blake3concatHasher(byte[] key){
        initialize(wordsFromLEBytes(key), KEYED_HASH);
    }


    private void initialize(int[] key, int flags){
        this.chunkState = new ChunkState(key, 0, flags);
        this.key = key;
        this.flags = flags;
    }

    /**
     * Appends new data to the hash tree
     * @param input Data to be added
     */
    public void update(byte[] input){
        update(input, 0, input.length);
    }

    private void update(byte[] input, int offset, int length){
        int currPos = offset;
        while(currPos < length + offset ) {

            // If this chunk has chained in 16 64 bytes of input, add its CV to the stack
            if (chunkState.len() == CHUNK_LEN) {
                int[] chunkCV = chunkState.createNode().chainingValue();
                long totalChunks = chunkState.chunkCounter + 1;
                addChunkChainingValue(chunkCV, totalChunks);
                chunkState = new ChunkState(key, totalChunks, flags);
            }

            int want = CHUNK_LEN - chunkState.len();
            int take = Math.min(want, input.length - currPos);
            chunkState.update(input, currPos, take);
            currPos+=take;
        }
    }

    private void pushStack(int[] cv){
        this.cvStack[this.cvStackLen] = cv;
        cvStackLen+=1;
    }

    private int[] popStack(){
        this.cvStackLen-=1;
        return cvStack[cvStackLen];
    }

    // Combines the chaining values of two children to create the parent node
    private static Node parentNode(int[] leftChildCV, int[] rightChildCV, int[] key, int flags){
        int[] blockWords = new int[16];
        int i = 0;
        for(int x: leftChildCV){
            blockWords[i] = x;
            i+=1;
        }
        for(int x: rightChildCV){
            blockWords[i] = x;
            i+=1;
        }
        return new Node(key, blockWords, BLOCK_LEN, PARENT | flags);
    }

    private static int[] parentCV(int[] leftChildCV, int[] rightChildCV, int[] key, int flags){
        return parentNode(leftChildCV, rightChildCV, key, flags).chainingValue();
    }

    private void addChunkChainingValue(int[] newCV, long totalChunks){
        while((totalChunks & 1) == 0){
            newCV = parentCV(popStack(), newCV, key, flags);
            totalChunks >>=1;
        }
        pushStack(newCV);
    }
  }
}