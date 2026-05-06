import python

private predicate attrCall(Call c, string objectName, string memberName) {
  exists(Attribute a, Name n |
    a = c.getFunc() and
    n = a.getObject() and
    n.getId() = objectName and
    a.getName() = memberName
  )
}

private predicate nameCall(Call c, string name) {
  c.getFunc().(Name).getId() = name
}

private predicate namedArg(Call c, string name, Expr value) {
  exists(Keyword k |
    k = c.getAKeyword() and
    k.getArg() = name and
    value = k.getValue()
  )
}

private predicate stringValue(Expr e, string value) {
  value = e.(StringLiteral).getText()
}

private predicate intValue(Expr e, int value) {
  value = e.(IntegerLiteral).getValue()
}

private predicate falseValue(Expr e) {
  e instanceof False
}

private predicate hashAlgorithmFromCall(Call c, string api, string algorithm, string evidence) {
  attrCall(c, "hashlib", "md5") and api = "hashlib.md5" and algorithm = "MD5" and evidence = "hashlib.md5"
  or
  attrCall(c, "hashlib", "sha1") and api = "hashlib.sha1" and algorithm = "SHA-1" and evidence = "hashlib.sha1"
  or
  attrCall(c, "hashlib", "sha256") and api = "hashlib.sha256" and algorithm = "SHA-256" and evidence = "hashlib.sha256"
  or
  attrCall(c, "hashlib", "sha384") and api = "hashlib.sha384" and algorithm = "SHA-384" and evidence = "hashlib.sha384"
  or
  attrCall(c, "hashlib", "sha512") and api = "hashlib.sha512" and algorithm = "SHA-512" and evidence = "hashlib.sha512"
  or
  attrCall(c, "hashlib", "new") and stringValue(c.getArg(0), algorithm) and
  api = "hashlib.new" and evidence = "hashlib.new(" + algorithm + ")"
}

private predicate hmacAlgorithmFromCall(Call c, string api, string algorithm, string evidence) {
  attrCall(c, "hmac", "new") and
  (
    stringValue(c.getArg(2), algorithm) or
    exists(Expr digestmod | namedArg(c, "digestmod", digestmod) and stringValue(digestmod, algorithm))
  ) and
  api = "hmac.new" and
  evidence = "hmac.new digestmod=" + algorithm
}

private predicate rsaKeyGeneration(Call c, int keySize, string evidence) {
  attrCall(c, "rsa", "generate_private_key") and
  (
    exists(Expr size | namedArg(c, "key_size", size) and intValue(size, keySize))
    or
    intValue(c.getArg(1), keySize)
  ) and
  evidence = "rsa.generate_private_key key_size=" + keySize.toString()
}

private predicate ecKeyGeneration(Call c, string evidence) {
  attrCall(c, "ec", "generate_private_key") and
  evidence = "ec.generate_private_key"
}

private predicate cipherModeFromCall(Call c, string mode, string evidence) {
  (nameCall(c, "Cipher") or attrCall(c, "Cipher", "__call__")) and
  exists(Call modeCall, Attribute modeFunc |
    modeCall = c.getArg(1) and
    modeFunc = modeCall.getFunc() and
    modeFunc.getObject().(Name).getId() = "modes" and
    mode = modeFunc.getName() and
    evidence = "Cipher mode=" + mode
  )
}

private predicate sslProtocolExpr(Expr e, string protocol) {
  exists(Attribute a, Name n |
    a = e and
    n = a.getObject() and
    n.getId() = "ssl" and
    (
      a.getName() = "PROTOCOL_TLSv1" and protocol = "TLSv1.0" or
      a.getName() = "PROTOCOL_TLSv1_1" and protocol = "TLSv1.1" or
      a.getName() = "PROTOCOL_TLSv1_2" and protocol = "TLSv1.2" or
      a.getName() = "PROTOCOL_TLS_CLIENT" and protocol = "TLS"
    )
  )
}

private predicate sslProtocolCall(Call c, string protocol, string evidence) {
  attrCall(c, "ssl", "SSLContext") and
  sslProtocolExpr(c.getArg(0), protocol) and
  evidence = "ssl.SSLContext " + protocol
}

private predicate requestsVerifyDisabled(Call c, string api, string evidence) {
  exists(Expr verify |
    (
      attrCall(c, "requests", "get") and api = "requests.get" or
      attrCall(c, "requests", "post") and api = "requests.post" or
      attrCall(c, "requests", "request") and api = "requests.request"
    ) and
    namedArg(c, "verify", verify) and
    falseValue(verify) and
    evidence = api + " verify=False"
  )
}

bindingset[algorithm]
private predicate weakHash(string algorithm) {
  algorithm.toUpperCase() = "MD5" or
  algorithm.toUpperCase() = "SHA1" or
  algorithm.toUpperCase() = "SHA-1"
}

bindingset[algorithm]
private predicate sha2(string algorithm) {
  algorithm.toUpperCase() = "SHA-224" or
  algorithm.toUpperCase() = "SHA224" or
  algorithm.toUpperCase() = "SHA-256" or
  algorithm.toUpperCase() = "SHA256" or
  algorithm.toUpperCase() = "SHA-384" or
  algorithm.toUpperCase() = "SHA384" or
  algorithm.toUpperCase() = "SHA-512" or
  algorithm.toUpperCase() = "SHA512"
}

bindingset[algorithm]
private predicate hashRisk(string algorithm, string riskLevel, string riskReason, string pqcStatus) {
  weakHash(algorithm) and riskLevel = "HIGH" and riskReason = "Broken hash" and pqcStatus = "UNKNOWN"
  or
  not weakHash(algorithm) and sha2(algorithm) and riskLevel = "LOW" and riskReason = "Modern hash" and pqcStatus = "SAFE"
  or
  not weakHash(algorithm) and not sha2(algorithm) and riskLevel = "LOW" and riskReason = "No known weak pattern" and pqcStatus = "UNKNOWN"
}

bindingset[protocol]
private predicate protocolRisk(string protocol, string riskLevel, string riskReason) {
  (protocol = "TLSv1.0" or protocol = "TLSv1.1") and riskLevel = "HIGH" and riskReason = "Deprecated protocol"
  or
  protocol = "TLSv1.2" and riskLevel = "MEDIUM" and riskReason = "Legacy protocol"
  or
  not protocol = "TLSv1.0" and not protocol = "TLSv1.1" and not protocol = "TLSv1.2" and
  riskLevel = "LOW" and riskReason = "Modern protocol"
}

private predicate pythonRecord(
  Call c, string api, string algorithm, string mode, int keySize, string protocol, string riskLevel,
  string riskReason, string pqcStatus, string harvestNowDecryptLaterRisk, string evidence
) {
  hashAlgorithmFromCall(c, api, algorithm, evidence) and
  mode = "" and keySize = -1 and protocol = "" and
  hashRisk(algorithm, riskLevel, riskReason, pqcStatus) and
  harvestNowDecryptLaterRisk = "false"
  or
  hmacAlgorithmFromCall(c, api, algorithm, evidence) and
  mode = "" and keySize = -1 and protocol = "" and
  hashRisk(algorithm, riskLevel, riskReason, pqcStatus) and
  harvestNowDecryptLaterRisk = "false"
  or
  rsaKeyGeneration(c, keySize, evidence) and
  api = "cryptography.rsa.generate_private_key" and algorithm = "RSA" and mode = "" and protocol = "" and
  (
    keySize < 2048 and riskLevel = "CRITICAL" and riskReason = "Weak key size"
    or
    keySize >= 2048 and riskLevel = "MEDIUM" and riskReason = "PQC vulnerable asymmetric crypto"
  ) and
  pqcStatus = "NOT_SAFE" and harvestNowDecryptLaterRisk = "true"
  or
  ecKeyGeneration(c, evidence) and
  api = "cryptography.ec.generate_private_key" and algorithm = "EC" and mode = "" and keySize = -1 and protocol = "" and
  riskLevel = "MEDIUM" and riskReason = "PQC vulnerable asymmetric crypto" and
  pqcStatus = "NOT_SAFE" and harvestNowDecryptLaterRisk = "true"
  or
  cipherModeFromCall(c, mode, evidence) and
  api = "cryptography.Cipher" and algorithm = "AES" and keySize = -1 and protocol = "" and
  (
    mode = "ECB" and riskLevel = "HIGH" and riskReason = "No authentication"
    or
    mode = "GCM" and riskLevel = "LOW" and riskReason = "Modern secure mode"
    or
    not mode = "ECB" and not mode = "GCM" and riskLevel = "LOW" and riskReason = "No known weak pattern"
  ) and
  pqcStatus = "SAFE" and harvestNowDecryptLaterRisk = "false"
  or
  sslProtocolCall(c, protocol, evidence) and
  api = "ssl.SSLContext" and algorithm = "" and mode = "" and keySize = -1 and
  protocolRisk(protocol, riskLevel, riskReason) and
  pqcStatus = "UNKNOWN" and harvestNowDecryptLaterRisk = "true"
  or
  requestsVerifyDisabled(c, api, evidence) and
  algorithm = "" and mode = "" and keySize = -1 and protocol = "TLS" and
  riskLevel = "HIGH" and riskReason = "TLS certificate verification disabled" and
  pqcStatus = "UNKNOWN" and harvestNowDecryptLaterRisk = "false"
}

from
  Call c,
  string file,
  int line,
  int startColumn,
  int endLine,
  int endColumn,
  string api,
  string algorithm,
  string mode,
  int keySize,
  string protocol,
  string riskLevel,
  string riskReason,
  string pqcStatus,
  string harvestNowDecryptLaterRisk,
  string evidence
where
  pythonRecord(
    c, api, algorithm, mode, keySize, protocol, riskLevel, riskReason, pqcStatus,
    harvestNowDecryptLaterRisk, evidence
  ) and
  c.getLocation().hasLocationInfo(file, line, startColumn, endLine, endColumn)
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
  harvestNowDecryptLaterRisk,
  "code",
  "python",
  "false",
  "HIGH",
  evidence
