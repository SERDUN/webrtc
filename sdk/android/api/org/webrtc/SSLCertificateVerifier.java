/*
 *  Copyright 2018 The WebRTC project authors. All Rights Reserved.
 *
 *  Use of this source code is governed by a BSD-style license
 *  that can be found in the LICENSE file in the root of the source
 *  tree. An additional intellectual property rights grant can be found
 *  in the file PATENTS.  All contributing project authors may
 *  be found in the AUTHORS file in the root of the source tree.
 */

package org.webrtc;

/**
 * The SSLCertificateVerifier interface allows API users to provide custom
 * logic to verify certificates.
 */
public interface SSLCertificateVerifier {
  /**
   * Implementations of verify allow applications to provide custom logic for
   * verifying certificates. This is not required by default and should be used
   * with care.
   *
   * @param certificate A byte array containing a DER encoded X509 certificate.
   * @return True if the certificate is verified and trusted else false.
   */
  @CalledByNative boolean verify(byte[] certificate);

  /**
   * Verifies the complete certificate chain for the actual TLS connection's hostname.
   * Override this method to apply hostname-specific trust policy without fetching certificates
   * from a second connection. Native WebRTC still checks the certificate's hostname separately.
   *
   * <p>The default preserves existing implementations, including lambdas, by passing only the
   * leaf to {@link #verify(byte[])}. As with that method, invocation and the effect of a rejection
   * follow the native SDK's certificate verification policy; this does not change trust precedence.
   *
   * @param chain DER encoded X509 certificates, leaf first, followed by intermediates.
   * @param hostname The TLS hostname, or an empty string if the caller did not supply one.
   */
  @CalledByNative
  default boolean verifyChain(byte[][] chain, String hostname) {
    return chain != null && chain.length != 0 && chain[0] != null && chain[0].length != 0
        && verify(chain[0]);
  }
}
