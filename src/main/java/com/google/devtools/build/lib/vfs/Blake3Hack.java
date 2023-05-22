// Copyright 2018 The Bazel Authors. All rights reserved.
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

package com.google.devtools.build.lib.vfs;

import static com.google.common.base.Preconditions.checkArgument;

import com.google.common.hash.HashFunction;

/**
 * Type of hash function to use for digesting files.
 *
 * <p>This tracks parallel {@link java.security.MessageDigest} and {@link HashFunction} interfaces
 * for each provided hash, as Bazel uses both - MessageDigest where performance is critical and
 * HashFunctions where ease-of-use wins over.
 */
// The underlying HashFunctions are immutable and thread safe.
public class Blake3Hack {

  private static class Blake3Holder {
    static final HashFunction BLAKE3 = null;
  }

  public static HashFunction blake3() {
    return Blake3Holder.BLAKE3;
  }
}
