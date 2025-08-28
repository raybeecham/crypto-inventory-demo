// Bring in the Java libraries + the modules that define MethodAccess, Expr, RefType
import java
import semmle.code.java.Expressions
import semmle.code.java.Types

/** JCA/JCE types to inventory */
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

/**
 * Single-select query:
 *  - Rows where Call=getInstance list the requested algorithm string
 *  - Rows where Call=initialize list the first argument (e.g., RSA key size)
 */
from MethodAccess m, string api, string callName, string key, string value
where
  // Case 1: inventory getInstance("...") on crypto classes
  (
    m.getMethod().hasName("getInstance") and
    isCryptoType(m.getMethod().getDeclaringType()) and
    exists(string alg | m.getArgument(0).getStringValue() = alg and value = alg) and
    api = m.getMethod().getDeclaringType().getQualifiedName() and
    callName = "getInstance" and
    key = "Algorithm"
  )
  or
  // Case 2: note KeyPairGenerator.initialize(...) arg0 (often key size)
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
