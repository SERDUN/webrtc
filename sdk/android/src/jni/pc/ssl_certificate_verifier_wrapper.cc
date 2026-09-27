/*
 *  Copyright 2018 The WebRTC project authors. All Rights Reserved.
 *
 *  Use of this source code is governed by a BSD-style license
 *  that can be found in the LICENSE file in the root of the source
 *  tree. An additional intellectual property rights grant can be found
 *  in the file PATENTS.  All contributing project authors may
 *  be found in the AUTHORS file in the root of the source tree.
 */

#include "sdk/android/src/jni/pc/ssl_certificate_verifier_wrapper.h"

#include <jni.h>

#include "rtc_base/buffer.h"
#include "rtc_base/ssl_certificate.h"
#include "sdk/android/generated_peerconnection_jni/SSLCertificateVerifier_jni.h"
#include "sdk/android/native_api/jni/java_types.h"
#include "sdk/android/native_api/jni/jvm.h"
#include "sdk/android/native_api/jni/scoped_java_ref.h"

namespace webrtc {
namespace jni {

SSLCertificateVerifierWrapper::SSLCertificateVerifierWrapper(
    JNIEnv* jni,
    const JavaRef<jobject>& ssl_certificate_verifier)
    : ssl_certificate_verifier_(jni, ssl_certificate_verifier) {}

SSLCertificateVerifierWrapper::~SSLCertificateVerifierWrapper() = default;

bool SSLCertificateVerifierWrapper::Verify(const SSLCertificate& certificate) {
  return VerifyChain(SSLCertChain(certificate.Clone()));
}

bool SSLCertificateVerifierWrapper::VerifyChain(const SSLCertChain& chain) {
  return VerifyChain(chain, "");
}

bool SSLCertificateVerifierWrapper::VerifyChain(const SSLCertChain& chain,
                                                absl::string_view hostname) {
  if (chain.GetSize() == 0) {
    return false;
  }

  JNIEnv* jni = AttachCurrentThreadIfNeeded();

  ScopedJavaLocalRef<jclass> byte_array_class =
      ScopedJavaLocalRef<jclass>::Adopt(jni, jni->FindClass("[B"));
  if (byte_array_class.is_null()) {
    return false;
  }
  ScopedJavaLocalRef<jobjectArray> der_chain =
      ScopedJavaLocalRef<jobjectArray>::Adopt(
          jni, jni->NewObjectArray(static_cast<jsize>(chain.GetSize()),
                                   byte_array_class.obj(), nullptr));
  if (der_chain.is_null()) {
    return false;
  }

  for (size_t i = 0; i < chain.GetSize(); ++i) {
    Buffer der;
    chain.Get(i).ToDER(&der);
    ScopedJavaLocalRef<jbyteArray> element =
        ScopedJavaLocalRef<jbyteArray>::Adopt(
            jni, jni->NewByteArray(static_cast<jsize>(der.size())));
    if (element.is_null()) {
      return false;
    }
    jni->SetByteArrayRegion(element.obj(), 0, static_cast<jsize>(der.size()),
                            reinterpret_cast<const jbyte*>(der.data()));
    jni->SetObjectArrayElement(der_chain.obj(), static_cast<jsize>(i),
                               element.obj());
  }

  return Java_SSLCertificateVerifier_verifyChain(
      jni, ssl_certificate_verifier_, der_chain,
      NativeToJavaString(jni, hostname));
}

}  // namespace jni
}  // namespace webrtc
