                                                    digital signature
code:

import hashlib
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_
from Crypto.Hash import SHA25
key = RSA.generate(2048)

signer = PKCS1_v1_5.new(key)

message = b"Hello, this is a message to be signed."

hash_obj = SHA256.new()
hash_obj.update(message)
digest = hash_obj.digest()

signature = signer.sign(hash_obj)

verifier = PKCS1_v1_5.new(key.publickey())
if verifier.verify(hash_obj, signature):
    print("Signature is valid.")
else:
    print("Signature is invalid.")

output:
Signature is valid.
