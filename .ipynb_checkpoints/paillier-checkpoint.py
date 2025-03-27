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
        self.mu = gmpy2.invert(self.L(gmpy2.powmod(self.g, self.lamb, self.n2)), self.n)

    def L(self, u):
        return (u - 1) // self.n

    def encrypt(self, message: int):
        assert 0 <= message < self.n
        while True:
            r = gmpy2.mpz_random(gmpy2.random_state(), self.n)
            if gmpy2.gcd(r, self.n) == 1:
                break

        c1 = gmpy2.powmod(self.g, message, self.n2)
        c2 = gmpy2.powmod(r, self.n, self.n2)
        return (c1 * c2) % self.n2

    def decrypt(self, ciphertext: int):
        u = gmpy2.powmod(ciphertext, self.lamb, self.n2)
        l = self.L(u)
        return (l * self.mu) % self.n


# Test de base
test = Paillier(512)
m = "Trying to encrypt this message using Paillier"
c = test.encrypt(string_to_int(m))
assert(int_to_string(test.decrypt(c)) == m)

# Propriétés homomorphes
m1 = 123
m2 = 456
c1 = test.encrypt(m1)
c2 = test.encrypt(m2)

# Addition homomorphe : E(m1) * E(m2) mod n^2 = E(m1 + m2)
add_cipher = (c1 * c2) % test.n2
assert(test.decrypt(add_cipher) == (m1 + m2) % test.n)

# Addition d’un message clair : E(m1) * g^m2 = E(m1 + m2)
add_plain = (c1 * gmpy2.powmod(test.g, m2, test.n2)) % test.n2
assert(test.decrypt(add_plain) == (m1 + m2) % test.n)

# Multiplication par un scalaire : E(m1)^m2 = E(m1 * m2)
mul_plain = gmpy2.powmod(c1, m2, test.n2)
assert(test.decrypt(mul_plain) == (m1 * m2) % test.n)
