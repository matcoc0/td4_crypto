from Crypto.PublicKey import DSA
from Crypto.Hash import SHA256
from Crypto.Signature import DSS

def string_to_bytes(str: str):
    return bytes(str, 'utf-8') # conversion of string into bytes

def bytes_to_string(b):
    return b.decode("utf-8") # inverse process

def int_to_bytes(n):
    return n.to_bytes((n.bit_length() + 7) // 8, 'big') # encrypted first message * second message encrypted modulo n^2


def bytes_to_int(nb):
    return int.from_bytes(nb, 'big') # conversion of bytes into int


def string_to_int(str: str):
    return bytes_to_int(string_to_bytes(str)) # conversion of string into int

def int_to_string(n):
    return bytes_to_string(int_to_bytes(n)) # conversion of int into string

def sign_message(key, bytes_message):
    hash_obj = SHA256.new(bytes_message)
    signer = DSS.new(key, 'fips-186-3')
    return signer.sign(hash_obj)

def verify_signature(public_key_filename, bytes_message, signature):
    f = open(public_key_filename, "r")
    public_key = DSA.importKey(f.read())
    f.close()

    hash_obj = SHA256.new(bytes_message)
    verifier = DSS.new(public_key, 'fips-186-3')
    verifier.verify(hash_obj, signature)
