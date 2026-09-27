/*
 *  Copyright 2026 The WebRTC project authors. All Rights Reserved.
 *
 *  Use of this source code is governed by a BSD-style license
 *  that can be found in the LICENSE file in the root of the source
 *  tree. An additional intellectual property rights grant can be found
 *  in the file PATENTS.  All contributing project authors may
 *  be found in the AUTHORS file in the root of the source tree.
 */

package org.webrtc;

import java.util.Arrays;

public class SSLCertificateVerifierTestHelper {
  @CalledByNative
  static SSLCertificateVerifier create(byte[] leaf, byte[] issuer, String hostname) {
    return new SSLCertificateVerifier() {
      @Override
      public boolean verify(byte[] certificate) {
        throw new AssertionError("The chain callback must be used");
      }

      @Override
      public boolean verifyChain(byte[][] chain, String actualHost) {
        return chain.length == 2 && Arrays.equals(leaf, chain[0]) && Arrays.equals(issuer, chain[1])
            && hostname.equals(actualHost);
      }
    };
  }

  @CalledByNative
  static SSLCertificateVerifier createLegacy(byte[] leaf) {
    return certificate -> Arrays.equals(leaf, certificate);
  }
}
