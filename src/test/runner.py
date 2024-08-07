#!/usr/bin/python3 -u

#
#  Copyright (C) Canonical, Ltd.
#
#  This program is free software; you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation; version 3.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
#

import os

failing_tests = []
n_tests = 0

tests = { 
  "Ciphers" : "cipher_test",
  "Deterministic Random Bit Generators" : "drbg_test",
  "Key Agreements" : "keyagreement",
  "Key Encapsulation Mechanisms" : "keyencapsulation",
  "Key Derivation Functions" : "kdf",
  "Message Digests" : "md",
  "Message Authentication Codes" : "mac",
  "Signatures" : "signature"
}

def run_native_test(name):
  return os.system(f"build/test/bin/{name} > /dev/null 2>&1")

for test in tests.keys():
  name = tests[test]
  print(f"Running native test {test}: ", end="")
  result = run_native_test(name)
  n_tests += 1
  if result:
    failing_tests.append(f"{name}(native)")
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
