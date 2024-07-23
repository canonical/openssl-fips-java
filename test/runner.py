#!/usr/bin/python3 -u

import os

JAVA_HOME = os.environ["JAVA_HOME"]
LIBPATH = os.environ["LIBPATH"]
CLASSPATH = "build/classes:build/test/classes" 
OPENS = "\\-\\-add-opens=java.base/javax.crypto=ALL-UNNAMED  \\-\\-add-opens=java.base/java.security=ALL-UNNAMED"
failing_tests = []
n_tests = 0

tests = { 
  "Ciphers" : ("cipher_test","CipherTest"),
  "Deterministic Random Bit Generators" : ("drbg_test", "DrbgTest"),
  "Key Agreements" : ("keyagreement", "KeyAgreementTest"),
  "Key Encapsulation Mechanisms" : ("keyencapsulation", "KeyEncapsulationTest"),
  "Key Derivation Functions" : ("kdf", "PBKDFTest"),
  "Message Digests" : ("md", "MDTest"),
  "Message Authentication Codes" : ("mac", "MacTest"),
  "Signatures" : ("signature", "SignatureTest"),
  "Provider Sanity" : (None, "ProviderSanityTest"),
  "SecureRandom/API" : (None, "SecureRandomApiTest"),
  "KeyAgreement/API"  : (None, "KeyAgreementApiTest"),
  "Key Encapsulation Mechanism/API": (None, "KeyEncapsulationApiTest"),
  "Cipher/API" : (None, "CipherApiTest"),
  "Mac/API" : (None, "MacApiTest"),
  "MessageDigest/API" : (None, "MDApiTest"),
  "Signature/API" : (None, "SignatureApiTest"),
  "Key Derivation Functions/API" : (None, "SecretKeyFactoryApiTest"),
}

def run_java_test(name):
  return os.system(f"{JAVA_HOME}/bin/java -Djava.library.path={LIBPATH} {OPENS} -cp {CLASSPATH} {name} >> build/test/test.out 2>&1")

def run_native_test(name):
  return os.system(f"build/test/bin/{name} >> build/test/test.out 2>&1")

for test in tests.keys():
  name = tests[test][0] 
  if name is None:
    continue
  print(f"Running native test {test}: ", end="")
  result = run_native_test(name)
  n_tests += 1
  if result:
    failing_tests.append(f"{name}(native)")
    print(" failed")
  else:
    print(" passed")

for test in tests.keys():
  jname = tests[test][1]
  if jname is None:
    continue
  print(f"Running java test {test}: ", end="")
  result = run_java_test(jname)
  n_tests += 1
  if result:
    failing_tests.append(f"{jname}(java)")
    print(" failed")
  else:
    print(" passed")

n_failed = len(failing_tests)
n_passed = n_tests - n_failed

print(f"Result: {n_passed} / {n_tests} tests passed")

if (len(failing_tests) > 0):
  print("Failing tests:")
  for test in failing_tests:
    print(test)
  print("Please look into build/test/test.out for details")
  exit(1)
