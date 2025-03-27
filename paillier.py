from utils import *
from Crypto.Util import number
import gmpy2

class Paillier:
    def __init__(self, bits):
        self.keyGen(bits)

    def keyGen(self, bits):
        while True:
            p = gmpy2.mpz(number.getPrime(bits))
            q = gmpy2.mpz(number.getPrime(bits))
            if gmpy2.gcd(p * q, (p - 1) * (q - 1)) == 1:
                break

        self.p = p
        self.q = q
        self.n = p * q
        self.n2 = self.n * self.n
        self.g = self.n + 1
        self.lamb = (p - 1) * (q - 1)
        # mu is the modular inverse of L(g^lambda mod n^2)
        self.mu = gmpy2.invert(self.L(gmpy2.powmod(self.g, self.lamb, self.n2)), self.n)

    def L(self, u):
        # L function used in decryption: L(u) = (u - 1) // n
        return (u - 1) // self.n

    def encrypt(self, message: int):
        # Encrypts a plaintext integer using Paillier encryption
        assert 0 <= message < self.n
        while True:
            r = gmpy2.mpz_random(gmpy2.random_state(), self.n)
            if gmpy2.gcd(r, self.n) == 1:
                break

        c1 = gmpy2.powmod(self.g, message, self.n2)
        c2 = gmpy2.powmod(r, self.n, self.n2)
        return (c1 * c2) % self.n2

    def decrypt(self, ciphertext: int):
        # Decrypts a Paillier ciphertext back to the original plaintext
        u = gmpy2.powmod(ciphertext, self.lamb, self.n2)
        l = self.L(u)
        return (l * self.mu) % self.n


# test phase

test = Paillier(512)
m = "messagetoencrypt"
c = test.encrypt(string_to_int(m))
assert(int_to_string(test.decrypt(c)) == m)

m1 = 123 # first message 
m2 = 456 # second message 
c1 = test.encrypt(m1) # first message encrypted
c2 = test.encrypt(m2) # second message encrypted

# 1st propriety: E(m1) * E(m2) = E(m1 + m2)
add_cipher = (c1 * c2) % test.n2
assert(test.decrypt(add_cipher) == (m1 + m2) % test.n) 

# 2nd propriety: E(m1) * g^m2 = E(m1 + m2)
add_plain = (c1 * gmpy2.powmod(test.g, m2, test.n2)) % test.n2 
assert(test.decrypt(add_plain) == (m1 + m2) % test.n)

# 3rd propriety: E(m1)^m2 = E(m1 * m2)
mul_plain = gmpy2.powmod(c1, m2, test.n2) 
assert(test.decrypt(mul_plain) == (m1 * m2) % test.n)