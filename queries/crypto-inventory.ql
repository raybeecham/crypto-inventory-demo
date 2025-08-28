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

from MethodAccess call, RefType owner, Expr arg, string alg
where call.getMethod().hasName("getInstance") and
      owner = call.getMethod().getDeclaringType() and
      isCryptoType(owner) and
      arg = call.getArgument(0) and
      alg = arg.getStringValue()
select call,
  "API", owner.getQualifiedName(),
  "Call", "getInstance",
  "Algorithm", alg

from MethodAccess init
where init.getMethod().getDeclaringType().hasQualifiedName("java.security", "KeyPairGenerator") and
      init.getMethod().getName() = "initialize" and
      init.getNumberOfArguments() >= 1
select init,
  "API", "java.security.KeyPairGenerator",
  "Call", "initialize",
  "Arg0", init.getArgument(0).toString()
