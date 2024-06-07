<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Diffie-Hellman Key Exchange</title>
</head>
<body>
<h2>Diffie-Hellman Key Exchange</h2>

<p>Public Parameters (p, g): <span id="publicParams"></span></p>
<p>Private Key (a): <span id="privateKeyA"></span></p>
<p>Private Key (b): <span id="privateKeyB"></span></p>
<p>Shared Secret (computed by A): <span id="sharedSecretA"></span></p>
<p>Shared Secret (computed by B): <span id="sharedSecretB"></span></p>

<script>
function generatePrime() {
    return 23;
}

function generatePrimitiveRoot(p) {
    return 5;
}

function modPow(a, b, p) {
    return BigInt(a) ** BigInt(b) % BigInt(p);
}

function computePublicKey(privateKey, p, g) {
    return modPow(g, privateKey, p);
}

function computeSharedSecret(privateKey, publicKey, p) {
    return modPow(publicKey, privateKey, p);
}

const p = generatePrime();
const g = generatePrimitiveRoot(p);
document.getElementById('publicParams').innerText = '(' + p + ', ' + g + ')';

const privateKeyA = Math.floor(Math.random() * (p - 2) + 1);
const privateKeyB = Math.floor(Math.random() * (p - 2) + 1);
document.getElementById('privateKeyA').innerText = privateKeyA;
document.getElementById('privateKeyB').innerText = privateKeyB;

const publicKeyA = computePublicKey(privateKeyA, p, g);
const publicKeyB = computePublicKey(privateKeyB, p, g);

const sharedSecretA = computeSharedSecret(privateKeyA, publicKeyB, p);
const sharedSecretB = computeSharedSecret(privateKeyB, publicKeyA, p);

document.getElementById('sharedSecretA').innerText = sharedSecretA;
document.getElementById('sharedSecretB').innerText = sharedSecretB;

</script>
</body>
</html>

 





































from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature
import os

def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()

    # Serialize private key to PEM format
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # Serialize public key to PEM format
    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_key_pem, public_key_pem

def write_to_file(data, filename):
    with open(filename, 'wb') as f:
        f.write(data)

def create_files():
    private_key_pem, public_key_pem = generate_key_pair()
    write_to_file(public_key_pem, 'public_key.pem')

    # Assume you have a hashed message
    hashed_message = b"This is a hashed message"
    write_to_file(hashed_message, 'hashed_message.txt')

    # Placeholder signature
    placeholder_signature = b"ThisIsAPlaceholderSignature"
    write_to_file(placeholder_signature, 'signature.bin')

    print("Files created successfully.")

def verify_signature(public_key_file, signature_file, hashed_message_file):
    # Read public key from file
    with open(public_key_file, 'rb') as f:
        public_key_pem = f.read()

    public_key = serialization.load_pem_public_key(
        public_key_pem,
        backend=default_backend()
    )

    # Read hashed message from file
    with open(hashed_message_file, 'rb') as f:
        hashed_message = f.read()

    # Read signature from file
    with open(signature_file, 'rb') as f:
        signature = f.read()

    try:
        public_key.verify(
            signature,
            hashed_message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        print("Signature is valid. The message has not been altered.")
    except InvalidSignature:
        print("Signature is invalid. The message may have been altered or the signature is incorrect.")

# Create necessary files
create_files()

# Verify signature
public_key_file = 'public_key.pem'
signature_file = 'signature.bin'
hashed_message_file = 'hashed_message.txt'

verify_signature(public_key_file, signature_file, hashed_message_file)

 


















Diffie hellman
def prime_check(p):
    if p < 1:
        return -1
    elif p > 1:
        if p == 2:
            return 1
        for i in range(2, p):
            if p % i == 0:
                return -1
            return 1
def premitive_check(g, p, L):
    for i in range(1, p):
        L.append(pow(g, i) % p)
    for i in range(1, p):
        if L.count(i) > 1:
            L.clear()
            return -1
        return 1
L=[]
while 1:
    p=int(input("enter a p"))
    if(prime_check(p))==-1:
        print("please enter a prime number")
        continue
    break
while 1:
    G=int(input("Enter a primitive root of "))
    if(premitive_check(p,G,L))==-1:
        print("Number is not premitive of ",p)
        continue
    break

x1,x2=int(input("Enter The private key of user 1")),int(input("Enter a private key of user 2"))

while 1:
    if(x1>p or x2>p):
        print(f"Private key of both should be less than {p}")
        continue
    break
    
y1,y2=pow(G,x1)%p,pow(G,x2)%p
k1,k2=pow(y2,x1)%p,pow(y1,x2)%p
print("secret key of user 1 ",k1," secret key of user 2 ",k2)
if(k1==k2):
    print("key have been exschange")
else:
    print("Keys have not exchange")
 
RSA:
import random

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def extended_gcd(a, b):
    if a == 0:
        return b, 0, 1
    else:
        gcd, x, y = extended_gcd(b % a, a)
        return gcd, y - (b // a) * x, x

def mod_inverse(a, m):
    gcd, x, y = extended_gcd(a, m)
    if gcd != 1:
        raise Exception('Modular inverse does not exist')
    else:
        return x % m

def generate_keypair(p, q):
    n = p * q
    phi = (p - 1) * (q - 1)
    e = random.randrange(1, phi)
    while gcd(e, phi) != 1:
        e = random.randrange(1, phi)
    d = mod_inverse(e, phi)
    return ((e, n), (d, n))

def encrypt(public_key, plaintext):
    e, n = public_key
    encrypted_msg = [pow(ord(char), e, n) for char in plaintext]
    return encrypted_msg

def decrypt(private_key, encrypted_msg):
    d, n = private_key
    decrypted_msg = [chr(pow(char, d, n)) for char in encrypted_msg]
    return ''.join(decrypted_msg)
if __name__ == '__main__':
    # Example usage
    p = 61
    q = 53
    public_key, private_key = generate_keypair(p, q)
    message = "Hello, RSA!"
    encrypted_msg = encrypt(public_key, message)
    decrypted_msg = decrypt(private_key, encrypted_msg)
    print("Original message:", message)
    print("Encrypted message:", encrypted_msg)
    print("Decrypted message:", decrypted_msg)

 

