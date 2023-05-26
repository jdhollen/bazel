package com.google.devtools.build.lib.vfs;

import java.io.InputStreamReader;
import java.io.FileInputStream;
import java.util.Arrays;
import java.io.InputStream;
import java.io.IOException;
import com.google.common.hash.Hasher;
import com.google.common.hash.Hashing;
import com.google.common.hash.HashFunction;
import com.google.devtools.build.lib.hash.Blake3ConcatHashFunction;
import com.google.devtools.build.lib.hash.Blake3Hasher;

public class AHashCli {
    private enum Type {
        CONCAT,
        SHA,
        JAVA,
        TYLER
    }
    private static byte[] buf = new byte[8192];

    private static final HashFunction CONCAT_FN = new Blake3ConcatHashFunction();
    private static final HashFunction DIGEST_FN = new Blake3DigestHashFunction();
    private static final HashFunction SHA_FN = Hashing.sha256();

    private static void hash(Type t, InputStream in, String fp) throws IOException {
        Hasher hasher;
        switch (t) {
            case CONCAT:
                hasher = CONCAT_FN.newHasher();
                break;
            case TYLER:
                hasher = new Blake3Hasher();
                break;
            case JAVA:
                hasher = DIGEST_FN.newHasher();
                break;
            case SHA:
            default:
                hasher = SHA_FN.newHasher();
                break;
        }

        while (true) {
            int read = in.read(buf);
            if (read == -1) {
            break;
            }

            hasher.putBytes(buf, 0, read);
        }
        hasher.hash();
    }

    public static void main(String[] args) throws IOException, InterruptedException {
    Type t;
    if (args.length > 0 && args[0].equals("-j")) {
        System.out.println("Using BLAKE3 Java");
        t = Type.JAVA;
    } else if (args.length > 0 && args[0].equals("-t")) {
        System.out.println("Using BLAKE3 Native");
        t = Type.TYLER;
    } else if (args.length > 0 && args[0].equals("-s")) {
        System.out.println("Using SHA-256");
        t = Type.SHA;
    } else if (args.length > 0 && args[0].equals("-c")) {
        System.out.println("Using BLAKE3-Concat");
        t = Type.CONCAT;
    } else {
        throw new IllegalArgumentException("Get out of here");
    }

    args = Arrays.copyOfRange(args, 1, args.length);

	if (args.length == 0) {
	    hash(t, System.in, "-");
	} else {
	        for (int i = 0; i < args.length; i++) {
		        InputStream inputStream = new FileInputStream(args[i]);
		        hash(t, inputStream, args[i]);
	        }
	}
    }
}