package com.google.devtools.build.lib.vfs;

import static com.google.common.base.Preconditions.checkArgument;
import static com.google.common.base.Preconditions.checkNotNull;
import static com.google.common.base.Preconditions.checkState;

import com.google.common.hash.Hasher;
import com.google.common.hash.HashCode;
import com.google.common.hash.HashFunction;
import com.google.errorprone.annotations.Immutable;
import java.io.InvalidObjectException;
import java.io.ObjectInputStream;
import java.io.Serializable;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;

/**
 * {@link HashFunction} adapter for {@link MessageDigest} instances.
 *
 * @author Kevin Bourrillion
 * @author Dimitris Andreou
 */
@Immutable
final class Blake3DigestHashFunction extends AbstractHashFunction {

  @SuppressWarnings("Immutable") // cloned before each use
  private final MessageDigest prototype;

  private final int bytes;
  private final boolean supportsClone;
  private final String toString;

  Blake3DigestHashFunction() {
    this.prototype = new Blake3MessageDigest(new BouncyBlake3());
    this.bytes = prototype.getDigestLength();
    this.toString = "BLAKE3";
    this.supportsClone = supportsClone(prototype);
  }

  private static boolean supportsClone(MessageDigest digest) {
    try {
      Object unused = digest.clone();
      return true;
    } catch (CloneNotSupportedException e) {
      return false;
    }
  }

  @Override
  public int bits() {
    return bytes * Byte.SIZE;
  }

  @Override
  public String toString() {
    return toString;
  }

  private static MessageDigest getMessageDigest(String algorithmName) {
      return new Blake3MessageDigest(new BouncyBlake3());
  }

  @Override
  public Hasher newHasher() {
    if (supportsClone) {
      try {
        return new MessageDigestHasher((MessageDigest) prototype.clone(), bytes);
      } catch (CloneNotSupportedException e) {
        // falls through
      }
    }
    return new MessageDigestHasher(getMessageDigest(prototype.getAlgorithm()), bytes);
  }

  private void readObject(ObjectInputStream stream) throws InvalidObjectException {
    throw new InvalidObjectException("Use SerializedForm");
  }

  /** Hasher that updates a message digest. */
  private static final class MessageDigestHasher extends AbstractByteHasher {
    private final MessageDigest digest;
    private final int bytes;
    private boolean done;

    private MessageDigestHasher(MessageDigest digest, int bytes) {
      this.digest = digest;
      this.bytes = bytes;
    }

    @Override
    protected void update(byte b) {
      checkNotDone();
      digest.update(b);
    }

    @Override
    protected void update(byte[] b, int off, int len) {
      checkNotDone();
      digest.update(b, off, len);
    }

    @Override
    protected void update(ByteBuffer bytes) {
      checkNotDone();
      digest.update(bytes);
    }

    private void checkNotDone() {
      checkState(!done, "Cannot re-use a Hasher after calling hash() on it");
    }

    @Override
    public HashCode hash() {
      checkNotDone();
      done = true;
      // XXX: This uses fromBytesNoCopy in guava, which isn't public, so there's
      // an extra copy here.
      // digest.digest();
      // return null;
      return (bytes == digest.getDigestLength())
          ? HashCode.fromBytes(digest.digest())
          : HashCode.fromBytes(Arrays.copyOf(digest.digest(), bytes));
    }
  }
}