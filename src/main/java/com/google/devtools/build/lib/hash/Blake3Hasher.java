package com.google.devtools.build.lib.hash;

import com.google.common.hash.HashCode;
import com.google.common.hash.Hasher;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.concurrent.locks.ReentrantLock;

public class Blake3Hasher extends AbstractHasher {
  // These constants match the native definitions in:
  // https://github.com/BLAKE3-team/BLAKE3/blob/master/c/blake3.h
  public static final int KEY_LEN = 32;
  public static final int OUT_LEN = 32;

  private static ThreadLocal<ByteBuffer> nativeByteBuffer = new ThreadLocal<ByteBuffer>();
  private static ThreadLocal<ByteBuffer> hashByteBuffer = new ThreadLocal<ByteBuffer>();
  private long hasher = -1;
  private int nbOffset = 0;
  private static final int FLUSH_LENGTH = 32;

  public boolean isValid() {
    return (hasher != -1);
  }

  private void checkValid() {
    if (!isValid()) {
      throw new IllegalStateException("Native hasher not initialized");
    }
  }

  public Blake3Hasher() throws IllegalStateException {
    // hasher = Blake3JNI.allocate_hasher();
    // checkValid();
    // checkValid();
    ByteBuffer byteBuff = nativeByteBuffer.get();
    ByteBuffer hashBuff = hashByteBuffer.get();
    if (byteBuff == null) {
      byteBuff = ByteBuffer.allocate(FLUSH_LENGTH * 2);
      byteBuff.order(ByteOrder.nativeOrder());
      nativeByteBuffer.set(byteBuff);

      hashBuff = ByteBuffer.allocateDirect(OUT_LEN);
      hashBuff.order(ByteOrder.nativeOrder());
      hashByteBuffer.set(hashBuff);
      Blake3JNI.blake3_take_arrays(byteBuff, hashBuff);
    }
    hasher = Blake3JNI.blake3_hasher_init();
  }

  public void close() {
    if (isValid()) {
        Blake3JNI.delete_hasher(hasher);
        hasher = -1;
    }
  }

  public void initDefault() {
    if (hasher != -1) {
      throw new IllegalStateException("Native hasher double-initialized");
    }
    hasher = Blake3JNI.blake3_hasher_init();
    checkValid();
  }

  public void initKeyed(byte[] key) {
    if (key.length != KEY_LEN) {
      throw new IllegalArgumentException("Invalid hasher key length");
    }

    Blake3JNI.blake3_hasher_init_keyed(hasher, key);
  }

  public void initDeriveKey(String context) {
    Blake3JNI.blake3_hasher_init_derive_key(hasher, context);
  }

  public void update(byte[] data) {
    update(data, 0, data.length);
  }

  public void update(byte[] data, int offset, int length) {
    ByteBuffer byteBuff = nativeByteBuffer.get();

    if (byteBuff == null || byteBuff.capacity() < nbOffset + length) {
      ByteBuffer prev = byteBuff;
      byteBuff = ByteBuffer.allocate(nbOffset + length);
      byteBuff.order(ByteOrder.nativeOrder());
      nativeByteBuffer.set(byteBuff);
      byteBuff.rewind();
      if (nbOffset > 0) {
        byteBuff.put(prev);
      }
    }
    byteBuff.put(data, offset, length);
    nbOffset = nbOffset + length;

    if (nbOffset < FLUSH_LENGTH) {
      return;
    } else if(hasher == -1) {
      hasher = Blake3JNI.blake3_hasher_init_and_flush(0, nbOffset);
    } else {
      Blake3JNI.blake3_hasher_update(byteBuff.array(), nbOffset);
    }
    byteBuff.rewind();
    nbOffset = 0;
  }

  @Override
  public HashCode hash() {
    ByteBuffer hashBuff = hashByteBuffer.get();
    if (hashBuff == null) {
      hashBuff = ByteBuffer.allocateDirect(OUT_LEN);
      hashBuff.order(ByteOrder.nativeOrder());
      hashByteBuffer.set(hashBuff);
    }
    hashBuff.rewind();

    ByteBuffer byteBuff = nativeByteBuffer.get();
    if (byteBuff == null) {
      byteBuff = ByteBuffer.allocate(1);
      byteBuff.order(ByteOrder.nativeOrder());
      nativeByteBuffer.set(byteBuff);
    }

    if(hasher == -1) {
      hasher = Blake3JNI.blake3_hasher_init_and_flush_and_finalize(nbOffset, OUT_LEN);
    } else {
      Blake3JNI.blake3_hasher_flush_and_finalize(hasher, byteBuff.array(), 0, OUT_LEN);
    }
    byte[] retByteArray = new byte[OUT_LEN];
    hashBuff.get(retByteArray);

    nbOffset = 0;
    byteBuff.rewind();
    hashBuff.rewind();
    return HashCode.fromBytes(retByteArray);
    
  }

  @Override
  public Hasher putBytes(byte[] bytes, int off, int len) {
    update(bytes, off, len);
    return this;
  }

  @Override
  public Hasher putByte(byte b) {
    new RuntimeException().printStackTrace();
    update(new byte[] {b}, 0, 1);
    return this;
  }
}
