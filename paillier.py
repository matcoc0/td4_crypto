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


# test phase
test = Paillier(512)
m = "messagetoencrypt"
c = test.encrypt(string_to_int(m))
assert(int_to_string(test.decrypt(c)) == m)

# proprieties
m1 = 123 # first message 
m2 = 456 # second message 
c1 = test.encrypt(m1) # first message encrypted
c2 = test.encrypt(m2) # second message encrypted

## Addition homomorphe : E(m1) * E(m2) mod n^2 = E(m1 + m2)
add_cipher = (c1 * c2) % test.n2 # encyptions addition : first message encrypted * second message encrypted modulo n
assert(test.decrypt(add_cipher) == (m1 + m2) % test.n) # check of result

# Addition d’un message clair : E(m1) * g^m2 = E(m1 + m2)
add_plain = (c1 * gmpy2.powmod(test.g, m2, test.n2)) % test.n2 #addition of message : Encrypted message 1 *
assert(test.decrypt(add_plain) == (m1 + m2) % test.n)

# Multiplication par un scalaire : E(m1)^m2 = E(m1 * m2)
mul_plain = gmpy2.powmod(c1, m2, test.n2) # multiplication by scalar : E(m1)^m2
assert(test.decrypt(mul_plain) == (m1 * m2) % test.n) # test of result
