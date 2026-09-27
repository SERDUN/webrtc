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

import android.net.http.X509TrustManagerExtensions;
import androidx.annotation.Nullable;
import java.io.ByteArrayInputStream;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

/**
 * Validates a peer certificate chain against the platform trust store, for use when the trust
 * anchors compiled into rtc_base/ssl_roots.h contain no path for it.
 *
 * <p>Only reachable from native code; the chain arrives whole, so no certificate has to be fetched
 * to complete it. The actual TLS hostname selects the application's network security policy.
 * Hostname matching is not done here - OpenSSLAdapter checks it separately.
 */
final class PlatformCertificateVerifier {
  private static final String TAG = "PlatformCertificateVerifier";

  @Nullable private static X509TrustManagerExtensions trustManager;
  private static boolean initialized;

  private PlatformCertificateVerifier() {}

  private static synchronized boolean initialize() {
    if (initialized) {
      return trustManager != null;
    }
    initialized = true;
    try {
      TrustManagerFactory factory =
          TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
      // Use the application's policy, including its network security configuration.
      // User-installed authorities are trusted only when that policy permits them.
      factory.init((KeyStore) null);
      for (TrustManager candidate : factory.getTrustManagers()) {
        if (candidate instanceof X509TrustManager) {
          trustManager = new X509TrustManagerExtensions((X509TrustManager) candidate);
          break;
        }
      }
    } catch (Exception e) {
      Logging.e(TAG, "Could not reach the platform trust store", e);
      trustManager = null;
    }
    return trustManager != null;
  }

  /**
   * @param derChain peer certificates in DER form, leaf first.
   * @param hostname the actual TLS hostname, used to select the application's trust policy.
   * @return whether the chain terminates in an anchor the platform trusts.
   */
  @CalledByNative
  static boolean verifyServerChain(byte[][] derChain, String hostname) {
    if (derChain == null || derChain.length == 0 || hostname == null || hostname.isEmpty()
        || !initialize()) {
      return false;
    }
    final X509TrustManagerExtensions manager = trustManager;
    return manager != null && verifyServerChain(derChain, hostname, manager);
  }

  // Also used by tests with a host-specific policy, without replacing process-wide trust.
  static boolean verifyServerChain(
      byte[][] derChain, String hostname, X509TrustManagerExtensions manager) {
    if (derChain == null || derChain.length == 0 || hostname == null || hostname.isEmpty()) {
      return false;
    }

    try {
      // CertificateFactory has no thread-safety guarantee; callbacks may run concurrently.
      CertificateFactory factory = CertificateFactory.getInstance("X.509");
      List<X509Certificate> parsed = new ArrayList<>(derChain.length);
      for (byte[] der : derChain) {
        parsed.add(
            (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(der)));
      }
      X509Certificate[] chain = parsed.toArray(new X509Certificate[0]);

      // The key algorithm of the leaf stands in for the TLS key-exchange authType, which is not
      // available at this layer. Conscrypt uses it only to pick a validation profile.
      String authType = chain[0].getPublicKey().getAlgorithm();
      manager.checkServerTrusted(chain, authType == null ? "RSA" : authType, hostname);
      return true;
    } catch (Exception e) {
      Logging.d(TAG, "Peer certificate chain was rejected by the platform trust store: " + e);
      return false;
    }
  }
}
