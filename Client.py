from paillier import Paillier
import gmpy2

class Client:
    def __init__(self, bits):
        self.paillier = Paillier(bits)

    def request(self, db_size, index):
        """
        Creates a encrypted vector v where the only element in the given index is E(1), the others are E(0).
        It returns (v, public_key) to send it to the server.
        """
        v = []
        for i in range(db_size):
            if i == index:
                v.append(self.paillier.encrypt(1))
            else:
                v.append(self.paillier.encrypt(0))

        public_key = (self.paillier.n, self.paillier.g)
        return v, public_key

    def decryptAnswer(self, ciphertext):
        return self.paillier.decrypt(ciphertext)
