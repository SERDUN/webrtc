/*
 *  Copyright 2026 The WebRTC project authors. All Rights Reserved.
 *
 *  Use of this source code is governed by a BSD-style license
 *  that can be found in the LICENSE file in the root of the source
 *  tree. An additional intellectual property rights grant can be found
 *  in the file PATENTS.  All contributing project authors may
 *  be found in the AUTHORS file in the root of the source tree.
 */

#include <cstdint>
#include <memory>
#include <span>
#include <utility>
#include <vector>

#include "rtc_base/buffer.h"
#include "rtc_base/ssl_certificate.h"
#include "rtc_base/ssl_identity.h"
#include "sdk/android/generated_native_unittests_jni/SSLCertificateVerifierTestHelper_jni.h"
#include "sdk/android/native_api/jni/java_types.h"
#include "sdk/android/native_api/jni/jvm.h"
#include "sdk/android/src/jni/pc/ssl_certificate_verifier_wrapper.h"
#include "test/gtest.h"

namespace webrtc {
namespace jni {
namespace {

ScopedJavaLocalRef<jbyteArray> Encode(JNIEnv* env,
                                      const SSLCertificate& certificate) {
  Buffer der;
  certificate.ToDER(&der);
  return NativeToJavaByteArray(
      env, std::span(reinterpret_cast<int8_t*>(der.data()), der.size()));
}

TEST(SSLCertificateVerifierWrapperTest, ForwardsChainAndHostname) {
  auto leaf = SSLIdentity::Create("leaf.invalid", KeyParams::ECDSA());
  auto issuer = SSLIdentity::Create("issuer.invalid", KeyParams::ECDSA());
  ASSERT_TRUE(leaf != nullptr);
  ASSERT_TRUE(issuer != nullptr);
  std::vector<std::unique_ptr<SSLCertificate>> certs;
  certs.push_back(leaf->certificate().Clone());
  certs.push_back(issuer->certificate().Clone());
  SSLCertChain chain(std::move(certs));

  JNIEnv* env = AttachCurrentThreadIfNeeded();
  auto java_verifier = Java_SSLCertificateVerifierTestHelper_create(
      env, Encode(env, chain.Get(0)), Encode(env, chain.Get(1)),
      NativeToJavaString(env, "turn.example"));
  SSLCertificateVerifierWrapper verifier(env, java_verifier);
  EXPECT_TRUE(verifier.VerifyChain(chain, "turn.example"));
  EXPECT_FALSE(verifier.VerifyChain(chain, "other.example"));
  EXPECT_FALSE(verifier.VerifyChain(chain));
  SSLCertChain empty((std::vector<std::unique_ptr<SSLCertificate>>()));
  EXPECT_FALSE(verifier.VerifyChain(empty, "turn.example"));
}

TEST(SSLCertificateVerifierWrapperTest, PreservesLegacyJavaVerifier) {
  auto identity = SSLIdentity::Create("leaf.invalid", KeyParams::ECDSA());
  ASSERT_TRUE(identity != nullptr);
  JNIEnv* env = AttachCurrentThreadIfNeeded();
  auto java_verifier = Java_SSLCertificateVerifierTestHelper_createLegacy(
      env, Encode(env, identity->certificate()));
  SSLCertificateVerifierWrapper verifier(env, java_verifier);
  std::vector<std::unique_ptr<SSLCertificate>> certs;
  certs.push_back(identity->certificate().Clone());
  certs.push_back(identity->certificate().Clone());
  SSLCertChain chain(std::move(certs));
  EXPECT_TRUE(verifier.VerifyChain(chain, "turn.example"));
  EXPECT_TRUE(verifier.Verify(identity->certificate()));
}

}  // namespace
}  // namespace jni
}  // namespace webrtc
