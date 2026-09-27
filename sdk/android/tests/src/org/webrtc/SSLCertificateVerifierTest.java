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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

import androidx.test.runner.AndroidJUnit4;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.robolectric.annotation.Config;

@RunWith(AndroidJUnit4.class)
@Config(manifest = Config.NONE)
public class SSLCertificateVerifierTest {
  @Test
  public void legacyLambdaReceivesOnlyLeaf() {
    byte[] leaf = new byte[] {1};
    int[] calls = new int[1];
    SSLCertificateVerifier verifier = certificate -> {
      assertSame(leaf, certificate);
      ++calls[0];
      return true;
    };

    assertTrue(verifier.verifyChain(new byte[][] {leaf, new byte[] {2}}, "turn.test"));
    assertEquals(1, calls[0]);
  }

  @Test
  public void legacyRefusalIsPreserved() {
    SSLCertificateVerifier verifier = certificate -> false;
    assertFalse(verifier.verifyChain(new byte[][] {{1}}, "turn.test"));
  }

  @Test
  public void missingLeafDoesNotInvokeLegacyVerifier() {
    SSLCertificateVerifier verifier = certificate -> {
      throw new AssertionError("No leaf was supplied");
    };
    assertFalse(verifier.verifyChain(null, "turn.test"));
    assertFalse(verifier.verifyChain(new byte[0][], "turn.test"));
    assertFalse(verifier.verifyChain(new byte[][] {null}, "turn.test"));
    assertFalse(verifier.verifyChain(new byte[][] {new byte[0]}, "turn.test"));
  }
}
