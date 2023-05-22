package com.google.devtools.build.lib.vfs;

import java.security.DigestException;
import java.security.MessageDigest;

public class Blake3MessageDigest
    extends MessageDigest
{
    protected BouncyBlake3 digest;
    protected int     digestSize;

    public Blake3MessageDigest(BouncyBlake3 blake3)
    {
        super(blake3.getAlgorithmName());

        this.digest = blake3;
        this.digestSize = blake3.getDigestSize();
    }

    public void engineReset() 
    {
        digest.reset();
    }

    public void engineUpdate(
        byte    input) 
    {
        digest.update(input);
    }

    public void engineUpdate(
        byte[]  input,
        int     offset,
        int     len) 
    {
        digest.update(input, offset, len);
    }

    public int engineGetDigestLength()
    {
        return digestSize;
    }

    public byte[] engineDigest() 
    {
        byte[]  digestBytes = new byte[digestSize];

        digest.doFinal(digestBytes, 0);

        return digestBytes;
    }

    public int engineDigest(byte[] buf, int off, int len) throws DigestException
    {
        if (len < digestSize)
            throw new DigestException("partial digests not returned");
        if (buf.length - off < digestSize)
            throw new DigestException("insufficient space in the output buffer to store the digest");

        digest.doFinal(buf, off);

        return digestSize;
    }
}