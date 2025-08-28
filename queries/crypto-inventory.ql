import java

predicate isCryptoType(RefType t) {
  t.hasQualifiedName("java.security", "MessageDigest") or
  t.hasQualifiedName("javax.crypto", "Cipher") or
  t.hasQualifiedName("java.security", "Signature") or
  t.hasQualifiedName("javax.crypto", "Mac") or
  t.hasQualifiedName("java.security", "KeyPairGenerator") or
  t.hasQualifiedName("java.security", "KeyFactory") or
  t.hasQualifiedName("java.security", "SecureRandom") or
  t.hasQualifiedName("javax.net.ssl", "SSLContext")
}

from MethodAccess m, string api, string callName, string key, string value
where
  (
    m.getMethod().hasName("getInstance") and
    isCryptoType(m.getMethod().getDeclaringType()) and
    exists(string alg | m.getArgument(0).getStringValue() = alg and value = alg) and
    api = m.getMethod().getDeclaringType().getQualifiedName() and
    callName = "getInstance" and
    key = "Algorithm"
  )
  or
  (
    m.getMethod().getDeclaringType().hasQualifiedName("java.security","KeyPairGenerator") and
    m.getMethod().getName() = "initialize" and
    m.getNumberOfArguments() >= 1 and
    api = "java.security.KeyPairGenerator" and
    callName = "initialize" and
    key = "Arg0" and
    value = m.getArgument(0).toString()
  )
select m, "API", api, "Call", callName, key, value
