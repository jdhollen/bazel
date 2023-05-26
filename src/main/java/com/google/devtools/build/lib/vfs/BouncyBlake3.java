package com.google.devtools.build.lib.vfs;

import java.util.Iterator;
import java.util.Stack;

/**
 * Blake3 implementation.
 */
public class BouncyBlake3
{

    private static final int INTEGERS_SIZE = Integer.SIZE;
    private static final int INTEGERS_BYTES = 4;
    /**
     * Already outputting error.
     */
    private static final String ERR_OUTPUTTING = "Already outputting";

    /**
     * Number of Words.
     */
    private static final int NUMWORDS = 8;

    /**
     * Number of Rounds.
     */
    private static final int ROUNDS = 7;

    /**
     * Buffer length.
     */
    private static final int BLOCKLEN = NUMWORDS * INTEGERS_BYTES * 2;

    /**
     * Chunk length.
     */
    private static final int CHUNKLEN = 1024;

    /**
     * ChunkStart Flag.
     */
    private static final int CHUNKSTART = 1;

    /**
     * ChunkEnd Flag.
     */
    private static final int CHUNKEND = 2;

    /**
     * Parent Flag.
     */
    private static final int PARENT = 4;

    /**
     * Root Flag.
     */
    private static final int ROOT = 8;

    /**
     * KeyedHash Flag.
     */
    private static final int KEYEDHASH = 16;

    /**
     * DeriveContext Flag.
     */
    private static final int DERIVECONTEXT = 32;

    /**
     * DeriveKey Flag.
     */
    private static final int DERIVEKEY = 64;

    /**
     * Chaining0 State Locations.
     */
    private static final int CHAINING0 = 0;

    /**
     * Chaining1 State Location.
     */
    private static final int CHAINING1 = 1;

    /**
     * Chaining2 State Location.
     */
    private static final int CHAINING2 = 2;

    /**
     * Chaining3 State Location.
     */
    private static final int CHAINING3 = 3;

    /**
     * Chaining4 State Location.
     */
    private static final int CHAINING4 = 4;

    /**
     * Chaining5 State Location.
     */
    private static final int CHAINING5 = 5;

    /**
     * Chaining6 State Location.
     */
    private static final int CHAINING6 = 6;

    /**
     * Chaining7 State Location.
     */
    private static final int CHAINING7 = 7;

    /**
     * IV0 State Locations.
     */
    private static final int IV0 = 8;

    /**
     * IV1 State Location.
     */
    private static final int IV1 = 9;

    /**
     * IV2 State Location.
     */
    private static final int IV2 = 10;

    /**
     * IV3 State Location.
     */
    private static final int IV3 = 11;

    /**
     * Count0 State Location.
     */
    private static final int COUNT0 = 12;

    /**
     * Count1 State Location.
     */
    private static final int COUNT1 = 13;

    /**
     * DataLen State Location.
     */
    private static final int DATALEN = 14;

    /**
     * Flags State Location.
     */
    private static final int FLAGS = 15;

    /**
     * Message word permutations.
     */
    private static final byte[][] SIGMA = {
        {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
        {2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8},
        {3, 4, 10, 12, 13, 2, 7, 14, 6, 5, 9, 0, 11, 15, 8, 1},
        {10, 7, 12, 9, 14, 3, 13, 15, 4, 0, 11, 2, 5, 8, 1, 6},
        {12, 13, 9, 11, 15, 10, 14, 8, 7, 2, 5, 3, 0, 1, 6, 4},
        {9, 14, 11, 5, 8, 12, 15, 1, 13, 3, 0, 10, 2, 6, 4, 7},
        {11, 15, 5, 0, 1, 9, 8, 6, 14, 10, 2, 12, 3, 4, 7, 13},
    };

    /**
     * Blake3 Initialization Vector.
     */
    private static final int[] IV = {
        0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    };

    /**
     * The byte input/output buffer.
     */
    private final byte[] theBuffer = new byte[BLOCKLEN];

    /**
     * The key.
     */
    private final int[] theK = new int[NUMWORDS];

    /**
     * The chaining value.
     */
    private final int[] theChaining = new int[NUMWORDS];

    /**
     * The state.
     */
    private final int[] theV = new int[NUMWORDS << 1];

    /**
     * The message Buffer.
     */
    private final int[] theM = new int[NUMWORDS << 1];

    /**
     * The indices.
     */
    private byte[] theIndices = SIGMA[0];

    /**
     * The chainingStack.
     */
    private final Stack theStack = new Stack();

    /**
     * The default digestLength.
     */
    private final int theDigestLen;

    /**
     * Are we outputting?
     */
    private boolean outputting;

    /**
     * How many more bytes can we output?
     */
    private long outputAvailable;

    /**
     * The current mode.
     */
    private int theMode;

    /**
     * The output mode.
     */
    private int theOutputMode;

    /**
     * The output dataLen.
     */
    private int theOutputDataLen;

    /**
     * The block counter.
     */
    private long theCounter;

    /**
     * The # of bytes in the current block.
     */
    private int theCurrBytes;

    /**
     * The position of the next byte in the buffer.
     */
    private int thePos;

    /**
     * Constructor.
     */
    public BouncyBlake3()
    {
        this((BLOCKLEN >> 1) * 8);
    }

    /**
     *
     * @param pDigestSize size of digest (in bits)
     */
    public BouncyBlake3(final int pDigestSize)
    {
        theDigestLen = pDigestSize / 8;

        // XXX.
        // CryptoServicesRegistrar.checkConstraints(Utils.getDefaultProperties(this, getDigestSize() * 8, purpose));

        init();
    }

    public int getByteLength()
    {
        return BLOCKLEN;
    }

    public String getAlgorithmName()
    {
        return "BLAKE3";
    }

    public int getDigestSize()
    {
        return theDigestLen;
    }

    /**
     * Initialise.
     *
     * @param pParams the parameters.
     */
    public void init()
    {
        /* Reset the digest */
        reset();
        initNullKey();
        theMode = 0;
    }

    public void update(final byte b)
    {
        /* Check that we are not outputting */
        if (outputting)
        {
            throw new IllegalStateException(ERR_OUTPUTTING);
        }

        /* If the buffer is full */
        final int blockLen = theBuffer.length;
        final int remainingLength = blockLen - thePos;
        if (remainingLength == 0)
        {
            /* Process the buffer */
            compressBlock(theBuffer, 0);

            /* Reset the buffer */
            fill(theBuffer, (byte)0);
            thePos = 0;
        }

        /* Store the byte */
        theBuffer[thePos] = b;
        thePos++;
    }

    public void update(final byte[] pMessage,
                       final int pOffset,
                       final int pLen)
    {
        /* Ignore null operation */
        if (pMessage == null || pLen == 0)
        {
            return;
        }

        /* Check that we are not outputting */
        if (outputting)
        {
            throw new IllegalStateException(ERR_OUTPUTTING);
        }

        /* Process any bytes currently in the buffer */
        boolean reset = false;
        int remainingLen = 0; // left bytes of buffer
        if (thePos != 0)
        {
            /* Calculate space remaining in the buffer */
            remainingLen = BLOCKLEN - thePos;

            /* If there is sufficient space in the buffer */
            if (remainingLen >= pLen)
            {
                /* Copy data into buffer and return */
                System.arraycopy(pMessage, pOffset, theBuffer, thePos, pLen);
                thePos += pLen;
                return;
            }

            /* Fill the buffer */
            System.arraycopy(pMessage, pOffset, theBuffer, thePos, remainingLen);

            /* Process the buffer */
            compressBlock(theBuffer, 0);

            reset = true;
            /* Reset the buffer */
            thePos = 0;
            //fill(theBuffer, (byte)0);
        }

        /* process all blocks except the last one */
        int messagePos;
        final int blockWiseLastPos = pOffset + pLen - BLOCKLEN;
        for (messagePos = pOffset + remainingLen; messagePos < blockWiseLastPos; messagePos += BLOCKLEN)
        {
            /* Process the buffer */
            compressBlock(pMessage, messagePos);
        }

        /* Fill the buffer with the remaining bytes of the message */
        final int len = pLen - messagePos;
        System.arraycopy(pMessage, messagePos, theBuffer, 0, pOffset + len);
        thePos += pOffset + len;
        fill(theBuffer, thePos, BLOCKLEN, (byte)0);
    }

    public int doFinal(final byte[] pOutput,
                       final int pOutOffset)
    {
        return doFinal(pOutput, pOutOffset, getDigestSize());
    }

    public int doFinal(final byte[] pOut,
                       final int pOutOffset,
                       final int pOutLen)
    {
        /* Build the required output */
        final int length = doOutput(pOut, pOutOffset, pOutLen);

        /* reset the underlying digest and return the length */
        reset();
        return length;
    }

    public int doOutput(final byte[] pOut,
                        final int pOutOffset,
                        final int pOutLen)
    {
        if (pOutOffset > (pOut.length - pOutLen))
        {
            throw new RuntimeException("output buffer too short");
        }

        /* If we have not started outputting yet */
        if (!outputting)
        {
            /* Process the buffer */
            compressFinalBlock(thePos);
        }

        /* Reject if there is insufficient Xof remaining */
        if (pOutLen < 0
            || (outputAvailable >= 0 && pOutLen > outputAvailable))
        {
            throw new IllegalArgumentException("Insufficient bytes remaining");
        }

        /* If we have some remaining data in the current buffer */
        int dataLeft = pOutLen;
        int outPos = pOutOffset;
        if (thePos < BLOCKLEN)
        {
            /* Copy data from current hash */
            final int dataToCopy = Math.min(dataLeft, BLOCKLEN - thePos);
            System.arraycopy(theBuffer, thePos, pOut, outPos, dataToCopy);

            /* Adjust counters */
            thePos += dataToCopy;
            outPos += dataToCopy;
            dataLeft -= dataToCopy;
        }

        /* Loop until we have completed the request */
        while (dataLeft > 0)
        {
            /* Calculate the next block */
            nextOutputBlock();

            /* Copy data from current hash */
            final int dataToCopy = Math.min(dataLeft, BLOCKLEN);
            System.arraycopy(theBuffer, 0, pOut, outPos, dataToCopy);

            /* Adjust counters */
            thePos += dataToCopy;
            outPos += dataToCopy;
            dataLeft -= dataToCopy;
        }

        /* Adjust outputAvailable */
        outputAvailable -= pOutLen;

        /* Return the number of bytes transferred */
        return pOutLen;
    }

    public static void fill(byte[] a, byte val)
    {
        java.util.Arrays.fill(a, val);
    }

    public static void fill(byte[] a, int fromIndex, int toIndex, byte val)
    {
        java.util.Arrays.fill(a, fromIndex, toIndex, val);
    }

    public void reset()
    {
        resetBlockCount();
        thePos = 0;
        outputting = false;
        fill(theBuffer, (byte)0);
    }

    public static int[] clone(int[] data)
    {
        return null == data ? null : data.clone();
    }

    /**
     * Compress next block of the message.
     *
     * @param pMessage the message buffer
     * @param pMsgPos  the position within the message buffer
     */
    private void compressBlock(final byte[] pMessage,
                               final int pMsgPos)
    {
        /* Initialise state and compress message */
        initChunkBlock(BLOCKLEN, false);
        initM(pMessage, pMsgPos);
        compress();

        /* Adjust stack if we have completed a block */
        if (theCurrBytes == 0)
        {
            adjustStack();
        }
    }

    public static int[] copyOf(int[] original, int newLength)
    {
        int[] copy = new int[newLength];
        System.arraycopy(original, 0, copy, 0, Math.min(original.length, newLength));
        return copy;
    }

    /**
     * Adjust the stack.
     */
    private void adjustStack()
    {
        /* Loop to combine blocks */
        long myCount = theCounter;
        while (myCount > 0)
        {
            /* Break loop if we are not combining */
            if ((myCount & 1) == 1)
            {
                break;
            }

            /* Build the message to be hashed */
            final int[] myLeft = (int[])theStack.pop();
            System.arraycopy(myLeft, 0, theM, 0, NUMWORDS);
            System.arraycopy(theChaining, 0, theM, NUMWORDS, NUMWORDS);

            /* Create parent block */
            initParentBlock();
            compress();

            /* Next block */
            myCount >>= 1;
        }

        /* Add back to the stack */
        theStack.push(copyOf(theChaining, NUMWORDS));
    }

    /**
     * Compress final block.
     *
     * @param pDataLen the data length
     */
    private void compressFinalBlock(final int pDataLen)
    {
        /* Initialise state and compress message */
        initChunkBlock(pDataLen, true);
        initM(theBuffer, 0);
        compress();

        /* Finalise stack */
        processStack();
    }

    /**
     * Process the stack.
     */
    private void processStack()
    {
        /* Finalise stack */
        while (!theStack.isEmpty())
        {
            /* Build the message to be hashed */
            final int[] myLeft = (int[])theStack.pop();
            System.arraycopy(myLeft, 0, theM, 0, NUMWORDS);
            System.arraycopy(theChaining, 0, theM, NUMWORDS, NUMWORDS);

            /* Create parent block */
            initParentBlock();
            if (theStack.isEmpty())
            {
                setRoot();
            }
            compress();
        }
    }

    /**
     * Perform compression.
     */
    private void compress()
    {
        performRound(0);
        performRound(1);
        performRound(2);
        performRound(3);
        performRound(4);
        performRound(5);
        performRound(6);
        adjustChaining();
    }

    /**
     * Perform a round.
     */
    private void performRound(int round)
    {
        theIndices = SIGMA[round];
        
        mixG(CHAINING0, CHAINING4, IV0, COUNT0, theM[0],theM[1]);
        mixG(CHAINING1, CHAINING5, IV1, COUNT1, theM[2],theM[3]);
        mixG(CHAINING2, CHAINING6, IV2, DATALEN, theM[4],theM[5]);
        mixG(CHAINING3, CHAINING7, IV3, FLAGS, theM[6],theM[7]);

        /* Apply to diagonals of V */
        mixG(CHAINING0, CHAINING5, IV2, FLAGS, theM[8],theM[9]);
        mixG(CHAINING1, CHAINING6, IV3, COUNT0, theM[10],theM[11]);
        mixG(CHAINING2, CHAINING7, IV0, COUNT1, theM[12],theM[13]);
        mixG(CHAINING3, CHAINING4, IV1, DATALEN, theM[14],theM[15]);

        // /* Apply to columns of V */
        // mixG(CHAINING0, CHAINING4, IV0, COUNT0, theM[theIndices[0]],theM[theIndices[1]]);
        // mixG(CHAINING1, CHAINING5, IV1, COUNT1, theM[theIndices[2]],theM[theIndices[3]]);
        // mixG(CHAINING2, CHAINING6, IV2, DATALEN, theM[theIndices[4]],theM[theIndices[5]]);
        // mixG(CHAINING3, CHAINING7, IV3, FLAGS, theM[theIndices[6]],theM[theIndices[7]]);

        // /* Apply to diagonals of V */
        // mixG(CHAINING0, CHAINING5, IV2, FLAGS, theM[theIndices[8]],theM[theIndices[9]]);
        // mixG(CHAINING1, CHAINING6, IV3, COUNT0, theM[theIndices[10]],theM[theIndices[11]]);
        // mixG(CHAINING2, CHAINING7, IV0, COUNT1, theM[theIndices[12]],theM[theIndices[13]]);
        // mixG(CHAINING3, CHAINING4, IV1, DATALEN, theM[theIndices[14]],theM[theIndices[15]]);
    }

    /**
     * Initialise M from message.
     *
     * @param pMessage the source message
     * @param pMsgPos  the message position
     */
    private void initM(final byte[] pMessage,
                       final int pMsgPos)
    {
        /* Copy message bytes into word array */
        littleEndianToInt(pMessage, pMsgPos, theM);
    }

    public static void intToLittleEndian(int n, byte[] bs, int off)
    {
        bs[off] = (byte)(n);
        bs[++off] = (byte)(n >>> 8);
        bs[++off] = (byte)(n >>> 16);
        bs[++off] = (byte)(n >>> 24);
    }

    public static void intToLittleEndian(int[] ns, byte[] bs, int off)
    {
        for (int i = 0; i < ns.length; ++i)
        {
            intToLittleEndian(ns[i], bs, off);
            off += 4;
        }
    }

    /**
     * Adjust Chaining after compression.
     */
    private void adjustChaining()
    {
        /* If we are outputting */
        if (outputting)
        {
            /* Adjust full state */
            for (int i = 0; i < NUMWORDS; i++)
            {
                theV[i] ^= theV[i + NUMWORDS];
                theV[i + NUMWORDS] ^= theChaining[i];
            }

            /* Output state to buffer */
            intToLittleEndian(theV, theBuffer, 0);
            thePos = 0;

            /* Else just build chain value */
        }
        else
        {
            /* Combine V into Chaining */
            for (int i = 0; i < NUMWORDS; i++)
            {
                theChaining[i] = theV[i] ^ theV[i + NUMWORDS];
            }
        }
    }

    public static int rotateRight(int i, int distance)
    {
        return (i >>> distance) | (i << -distance);
    }

    /**
     * Mix function G.
     *
     * @param msgIdx the message index
     * @param posA   position A in V
     * @param posB   position B in V
     * @param posC   position C in V
     * @param posD   poistion D in V
     */
    private void mixG(final int posA,
                      final int posB,
                      final int posC,
                      final int posD,
                      final int x,
                      final int y)
    {
        /* Perform the Round */
        int i;
        theV[posA] += theV[posB] + x;

        i = theV[posD] ^ theV[posA];
        theV[posD] = (i >>> 16) | (i << 16);
        theV[posC] += theV[posD];

        i = theV[posB] ^ theV[posC];
        theV[posB] = (i >>> 12) | (i << 20);
        theV[posA] += theV[posB] + y;

        i = theV[posD] ^ theV[posA];
        theV[posD] = (i >>> 8) | (i << 24);
        theV[posC] += theV[posD];

        i = theV[posB] ^ theV[posC];
        theV[posB] = (i >>> 7) | (i << 25);
    }

    /**
     * initialise the indices.
     */
    private void initIndices()
    {
        theIndices = SIGMA[0];
    }

    /**
     * PermuteIndices.
     */
    private void permuteIndices(int round)
    {
        
    }

    /**
     * Initialise null key.
     */
    private void initNullKey()
    {
        System.arraycopy(IV, 0, theK, 0, NUMWORDS);
    }

    public static int littleEndianToInt(byte[] bs, int off)
    {
        int n = bs[off] & 0xff;
        n |= (bs[++off] & 0xff) << 8;
        n |= (bs[++off] & 0xff) << 16;
        n |= bs[++off] << 24;
        return n;
    }

    public static void littleEndianToInt(byte[] bs, int off, int[] ns)
    {
        int inneroff = off;
        for (int i = 0; i < ns.length; ++i)
        {
            inneroff = off;
            int n = bs[inneroff] & 0xff;
            n |= (bs[++inneroff] & 0xff) << 8;
            n |= (bs[++inneroff] & 0xff) << 16;
            n |= bs[++inneroff] << 24;
            ns[i] = n;
            off += 4;
        }
    }

    /**
     * Initialise key.
     *
     * @param pKey the keyBytes
     */
    private void initKey(final byte[] pKey)
    {
        /* Copy message bytes into word array */
        littleEndianToInt(pKey, 0, theK);
        theMode = KEYEDHASH;
    }

    /**
     * Initialise key from context.
     */
    private void initKeyFromContext()
    {
        System.arraycopy(theV, 0, theK, 0, NUMWORDS);
        theMode = DERIVEKEY;
    }

    /**
     * Initialise chunk block.
     *
     * @param pDataLen the dataLength
     * @param pFinal   is this the final chunk?
     */
    private void initChunkBlock(final int pDataLen,
                                final boolean pFinal)
    {
        /* Initialise the block */
        System.arraycopy(theCurrBytes == 0 ? theK : theChaining, 0, theV, 0, NUMWORDS);
        System.arraycopy(IV, 0, theV, NUMWORDS, NUMWORDS >> 1);
        theV[COUNT0] = (int)theCounter;
        theV[COUNT1] = (int)(theCounter >> INTEGERS_SIZE);
        theV[DATALEN] = pDataLen;
        theV[FLAGS] = theMode
            + (theCurrBytes == 0 ? CHUNKSTART : 0)
            + (pFinal ? CHUNKEND : 0);

        /* * Adjust block count */
        theCurrBytes += pDataLen;
        if (theCurrBytes >= CHUNKLEN)
        {
            incrementBlockCount();
            theV[FLAGS] |= CHUNKEND;
        }

        /* If we are single chunk */
        if (pFinal && theStack.isEmpty())
        {
            setRoot();
        }
    }

    /**
     * Initialise parent block.
     */
    private void initParentBlock()
    {
        /* Initialise the block */
        System.arraycopy(theK, 0, theV, 0, NUMWORDS);
        System.arraycopy(IV, 0, theV, NUMWORDS, NUMWORDS >> 1);
        theV[COUNT0] = 0;
        theV[COUNT1] = 0;
        theV[DATALEN] = BLOCKLEN;
        theV[FLAGS] = theMode | PARENT;
    }

    /**
     * Initialise output block.
     */
    private void nextOutputBlock()
    {
        /* Increment the counter */
        theCounter++;

        /* Initialise the block */
        System.arraycopy(theChaining, 0, theV, 0, NUMWORDS);
        System.arraycopy(IV, 0, theV, NUMWORDS, NUMWORDS >> 1);
        theV[COUNT0] = (int)theCounter;
        theV[COUNT1] = (int)(theCounter >> INTEGERS_SIZE);
        theV[DATALEN] = theOutputDataLen;
        theV[FLAGS] = theOutputMode;

        /* Generate output */
        compress();
    }

    /**
     * IncrementBlockCount.
     */
    private void incrementBlockCount()
    {
        theCounter++;
        theCurrBytes = 0;
    }

    /**
     * ResetBlockCount.
     */
    private void resetBlockCount()
    {
        theCounter = 0;
        theCurrBytes = 0;
    }

    /**
     * Set root indication.
     */
    private void setRoot()
    {
        theV[FLAGS] |= ROOT;
        theOutputMode = theV[FLAGS];
        theOutputDataLen = theV[DATALEN];
        theCounter = 0;
        outputting = true;
        outputAvailable = -1;
        System.arraycopy(theV, 0, theChaining, 0, NUMWORDS);
    }

}
