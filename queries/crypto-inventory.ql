import java

private predicate isCryptoGetInstanceType(RefType t) {
  t.hasQualifiedName("java.security", "MessageDigest") or
  t.hasQualifiedName("javax.crypto", "Cipher") or
  t.hasQualifiedName("java.security", "Signature") or
  t.hasQualifiedName("javax.crypto", "Mac") or
  t.hasQualifiedName("java.security", "KeyPairGenerator") or
  t.hasQualifiedName("javax.crypto", "KeyGenerator") or
  t.hasQualifiedName("java.security", "KeyFactory") or
  t.hasQualifiedName("javax.crypto", "SecretKeyFactory") or
  t.hasQualifiedName("java.security", "SecureRandom") or
  t.hasQualifiedName("javax.net.ssl", "SSLContext")
}

private predicate isKeySizeInitializeType(RefType t) {
  t.hasQualifiedName("java.security", "KeyPairGenerator") or
  t.hasQualifiedName("javax.crypto", "KeyGenerator")
}

private predicate getInstanceRecord(MethodCall m, string api, string raw, int keySize) {
  m.getMethod().hasName("getInstance") and
  isCryptoGetInstanceType(m.getMethod().getDeclaringType()) and
  m.getNumArgument() >= 1 and
  m.getArgument(0).getStringValue() = raw and
  api = m.getMethod().getDeclaringType().getQualifiedName() and
  keySize = -1
}

private predicate receiverAlgorithm(MethodCall init, string raw) {
  exists(VarAccess receiver, Variable v, MethodCall create |
    receiver = init.getQualifier() and
    receiver.getVariable() = v and
    create = v.getAnAssignedValue() and
    create.getMethod().hasName("getInstance") and
    isCryptoGetInstanceType(create.getMethod().getDeclaringType()) and
    create.getArgument(0).getStringValue() = raw
  )
}

private predicate literalKeySize(MethodCall m, int keySize) {
  exists(IntegerLiteral size |
    size = m.getArgument(0) and
    keySize = size.getIntValue()
  )
}

private predicate initializeRecord(MethodCall m, string api, string raw, int keySize) {
  m.getMethod().hasName("initialize") and
  isKeySizeInitializeType(m.getMethod().getDeclaringType()) and
  m.getNumArgument() >= 1 and
  api = m.getMethod().getDeclaringType().getQualifiedName() and
  literalKeySize(m, keySize) and
  (
    receiverAlgorithm(m, raw) or
    not exists(string alg | receiverAlgorithm(m, alg)) and raw = ""
  )
}

private predicate unknownSizeInitializeRecord(MethodCall m, string api, string raw, int keySize) {
  m.getMethod().hasName("initialize") and
  isKeySizeInitializeType(m.getMethod().getDeclaringType()) and
  m.getNumArgument() >= 1 and
  api = m.getMethod().getDeclaringType().getQualifiedName() and
  not exists(int size | literalKeySize(m, size)) and
  keySize = -1 and
  (
    receiverAlgorithm(m, raw) or
    not exists(string alg | receiverAlgorithm(m, alg)) and raw = ""
  )
}

private predicate cryptoRecord(MethodCall m, string api, string raw, int keySize) {
  getInstanceRecord(m, api, raw, keySize) or
  initializeRecord(m, api, raw, keySize) or
  unknownSizeInitializeRecord(m, api, raw, keySize)
}

private predicate knownAlgorithm(string api, string raw, string algorithm) {
  api = "javax.net.ssl.SSLContext" and algorithm = ""
  or
  exists(string upper |
    upper = raw.toUpperCase() and
    (
      upper = "MD5" and algorithm = "MD5"
      or
      (upper = "SHA1" or upper = "SHA-1") and algorithm = "SHA-1"
      or
      (upper = "SHA224" or upper = "SHA-224") and algorithm = "SHA-224"
      or
      (upper = "SHA256" or upper = "SHA-256") and algorithm = "SHA-256"
      or
      (upper = "SHA384" or upper = "SHA-384") and algorithm = "SHA-384"
      or
      (upper = "SHA512" or upper = "SHA-512") and algorithm = "SHA-512"
      or
      (upper = "SHA1WITHRSA" or upper = "SHA-1WITHRSA") and algorithm = "SHA1withRSA"
      or
      (upper = "SHA256WITHRSA" or upper = "SHA-256WITHRSA") and algorithm = "SHA256withRSA"
      or
      (upper = "SHA384WITHRSA" or upper = "SHA-384WITHRSA") and algorithm = "SHA384withRSA"
      or
      (upper = "SHA512WITHRSA" or upper = "SHA-512WITHRSA") and algorithm = "SHA512withRSA"
      or
      upper.matches("AES%") and algorithm = "AES"
      or
      upper.matches("DES/%") and algorithm = "DES"
      or
      upper = "DES" and algorithm = "DES"
      or
      upper.matches("DESEDE%") and algorithm = "3DES"
      or
      upper.matches("3DES%") and algorithm = "3DES"
      or
      upper.matches("RC4%") and algorithm = "RC4"
      or
      upper.matches("ARCFOUR%") and algorithm = "RC4"
      or
      (upper = "RSA" or upper.matches("RSA/%")) and algorithm = "RSA"
      or
      (upper = "EC" or upper = "ECC" or upper = "ECDSA" or upper = "ECDH") and algorithm = "EC"
      or
      upper = "DSA" and algorithm = "DSA"
      or
      upper = "DH" and algorithm = "DH"
      or
      upper = "SHA1PRNG" and algorithm = "SHA1PRNG"
    )
  )
}

private predicate algorithmValue(string api, string raw, string algorithm) {
  knownAlgorithm(api, raw, algorithm) or
  not exists(string a | knownAlgorithm(api, raw, a)) and algorithm = raw
}

private predicate extractedMode(string raw, string mode) {
  exists(string upper |
    upper = raw.toUpperCase() and
    (
      upper.matches("%/ECB/%") and mode = "ECB"
      or
      upper.matches("%/GCM/%") and mode = "GCM"
      or
      upper.matches("%/CBC/%") and mode = "CBC"
      or
      upper.matches("%/CTR/%") and mode = "CTR"
      or
      upper.matches("%/CFB/%") and mode = "CFB"
      or
      upper.matches("%/OFB/%") and mode = "OFB"
    )
  )
}

private predicate modeValue(string raw, string mode) {
  extractedMode(raw, mode) or
  not exists(string m | extractedMode(raw, m)) and mode = ""
}

private predicate protocolValue(string api, string raw, string protocol) {
  api = "javax.net.ssl.SSLContext" and protocol = raw
  or
  api != "javax.net.ssl.SSLContext" and protocol = ""
}

private predicate weakHash(string raw) {
  exists(string upper |
    upper = raw.toUpperCase() and
    (upper = "MD5" or upper = "SHA1" or upper = "SHA-1")
  )
}

private predicate weakSignature(string raw) {
  exists(string upper |
    upper = raw.toUpperCase() and
    (
      upper.matches("SHA1WITH%") or
      upper.matches("SHA-1WITH%") or
      upper.matches("MD5WITH%")
    )
  )
}

private predicate deprecatedCipher(string raw, string algorithm) {
  exists(string upper |
    upper = raw.toUpperCase() and
    (
      algorithm = "DES" or
      algorithm = "3DES" or
      algorithm = "RC4" or
      upper.matches("DES/%") or
      upper.matches("DESEDE%") or
      upper.matches("3DES%") or
      upper.matches("RC4%") or
      upper.matches("ARCFOUR%")
    )
  )
}

private predicate tls10Or11(string protocol) {
  exists(string upper |
    upper = protocol.toUpperCase() and
    (upper = "TLSV1" or upper = "TLSV1.0" or upper = "TLSV1.1" or upper = "SSL" or upper.matches("SSLV%"))
  )
}

private predicate tls12(string protocol) {
  protocol.toUpperCase() = "TLSV1.2"
}

private predicate asymmetricAlgorithm(string raw, string algorithm) {
  exists(string upper |
    upper = raw.toUpperCase() and
    (
      algorithm = "RSA" or
      algorithm = "EC" or
      algorithm = "DSA" or
      algorithm = "DH" or
      upper.matches("%WITHRSA") or
      upper.matches("%WITHECDSA") or
      upper.matches("%WITHDSA") or
      upper = "ECDH" or
      upper = "ECDSA"
    )
  )
}

private predicate weakAsymmetricKeySize(string api, string raw, string algorithm, int keySize) {
  keySize > -1 and
  (
    keySize < 2048 and
    (
      algorithm = "RSA" or
      algorithm = "DSA" or
      algorithm = "DH" or
      api = "java.security.KeyPairGenerator" and algorithm = "" or
      raw.toUpperCase().matches("%WITHRSA") or
      raw.toUpperCase().matches("%WITHDSA")
    )
    or
    algorithm = "EC" and keySize < 224
  )
}

private predicate criticalRisk(string api, string raw, string algorithm, int keySize) {
  weakAsymmetricKeySize(api, raw, algorithm, keySize)
}

private predicate highRisk(string raw, string algorithm, string mode, string protocol) {
  weakHash(raw) or
  weakSignature(raw) or
  mode = "ECB" or
  deprecatedCipher(raw, algorithm) or
  tls10Or11(protocol)
}

private predicate mediumRisk(string raw, string algorithm, string protocol) {
  tls12(protocol) or
  algorithm = "SHA1PRNG" or
  asymmetricAlgorithm(raw, algorithm)
}

private predicate riskClassification(
  string api, string raw, string algorithm, string mode, int keySize, string protocol, string riskLevel, string riskReason
) {
  criticalRisk(api, raw, algorithm, keySize) and riskLevel = "CRITICAL" and riskReason = "Weak key size"
  or
  not criticalRisk(api, raw, algorithm, keySize) and weakSignature(raw) and
  riskLevel = "HIGH" and riskReason = "Weak signature"
  or
  not criticalRisk(api, raw, algorithm, keySize) and not weakSignature(raw) and weakHash(raw) and
  riskLevel = "HIGH" and riskReason = "Broken hash"
  or
  not criticalRisk(api, raw, algorithm, keySize) and not weakSignature(raw) and not weakHash(raw) and mode = "ECB" and
  riskLevel = "HIGH" and riskReason = "No authentication"
  or
  not criticalRisk(api, raw, algorithm, keySize) and not weakSignature(raw) and not weakHash(raw) and mode != "ECB" and
  deprecatedCipher(raw, algorithm) and riskLevel = "HIGH" and riskReason = "Deprecated cipher"
  or
  not criticalRisk(api, raw, algorithm, keySize) and not weakSignature(raw) and not weakHash(raw) and mode != "ECB" and
  not deprecatedCipher(raw, algorithm) and tls10Or11(protocol) and
  riskLevel = "HIGH" and riskReason = "Deprecated protocol"
  or
  not criticalRisk(api, raw, algorithm, keySize) and not highRisk(raw, algorithm, mode, protocol) and tls12(protocol) and
  riskLevel = "MEDIUM" and riskReason = "Legacy protocol"
  or
  not criticalRisk(api, raw, algorithm, keySize) and not highRisk(raw, algorithm, mode, protocol) and not tls12(protocol) and
  algorithm = "SHA1PRNG" and riskLevel = "MEDIUM" and riskReason = "Legacy PRNG"
  or
  not criticalRisk(api, raw, algorithm, keySize) and not highRisk(raw, algorithm, mode, protocol) and not tls12(protocol) and
  algorithm != "SHA1PRNG" and mediumRisk(raw, algorithm, protocol) and
  riskLevel = "MEDIUM" and riskReason = "PQC vulnerable asymmetric crypto"
  or
  not criticalRisk(api, raw, algorithm, keySize) and not highRisk(raw, algorithm, mode, protocol) and not mediumRisk(raw, algorithm, protocol) and
  algorithm = "AES" and mode = "GCM" and riskLevel = "LOW" and riskReason = "Modern secure mode"
  or
  not criticalRisk(api, raw, algorithm, keySize) and not highRisk(raw, algorithm, mode, protocol) and not mediumRisk(raw, algorithm, protocol) and
  algorithm.matches("SHA-%") and riskLevel = "LOW" and riskReason = "Modern hash"
  or
  not criticalRisk(api, raw, algorithm, keySize) and not highRisk(raw, algorithm, mode, protocol) and not mediumRisk(raw, algorithm, protocol) and
  not (algorithm = "AES" and mode = "GCM") and not algorithm.matches("SHA-%") and
  riskLevel = "LOW" and riskReason = "No known weak pattern"
}

private predicate pqcSafeForNow(string algorithm) {
  algorithm = "AES" or
  algorithm = "SHA-224" or
  algorithm = "SHA-256" or
  algorithm = "SHA-384" or
  algorithm = "SHA-512"
}

private predicate pqcStatusValue(string raw, string algorithm, string pqcStatus) {
  asymmetricAlgorithm(raw, algorithm) and pqcStatus = "NOT_SAFE"
  or
  not asymmetricAlgorithm(raw, algorithm) and pqcSafeForNow(algorithm) and pqcStatus = "SAFE"
  or
  not asymmetricAlgorithm(raw, algorithm) and not pqcSafeForNow(algorithm) and pqcStatus = "UNKNOWN"
}

private predicate harvestNowDecryptLaterRiskValue(string api, string raw, string algorithm, string risk) {
  (
    api = "javax.net.ssl.SSLContext" or
    api = "java.security.KeyPairGenerator" and asymmetricAlgorithm(raw, algorithm) or
    api = "java.security.KeyFactory" and asymmetricAlgorithm(raw, algorithm) or
    api = "javax.crypto.Cipher" and algorithm = "RSA"
  ) and risk = "true"
  or
  not (
    api = "javax.net.ssl.SSLContext" or
    api = "java.security.KeyPairGenerator" and asymmetricAlgorithm(raw, algorithm) or
    api = "java.security.KeyFactory" and asymmetricAlgorithm(raw, algorithm) or
    api = "javax.crypto.Cipher" and algorithm = "RSA"
  ) and risk = "false"
}

from
  MethodCall m,
  string file,
  int line,
  int startColumn,
  int endLine,
  int endColumn,
  string api,
  string raw,
  string algorithm,
  string mode,
  int keySize,
  string protocol,
  string riskLevel,
  string riskReason,
  string pqcStatus,
  string harvestNowDecryptLaterRisk
where
  cryptoRecord(m, api, raw, keySize) and
  m.hasLocationInfo(file, line, startColumn, endLine, endColumn) and
  algorithmValue(api, raw, algorithm) and
  modeValue(raw, mode) and
  protocolValue(api, raw, protocol) and
  riskClassification(api, raw, algorithm, mode, keySize, protocol, riskLevel, riskReason) and
  pqcStatusValue(raw, algorithm, pqcStatus) and
  harvestNowDecryptLaterRiskValue(api, raw, algorithm, harvestNowDecryptLaterRisk)
select
  file,
  line,
  api,
  algorithm,
  mode,
  keySize,
  protocol,
  riskLevel,
  riskReason,
  pqcStatus,
  harvestNowDecryptLaterRisk
