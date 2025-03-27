import random
import gmpy2

class Server:
    def __init__(self, db_size):
        self.db_size = db_size
        self.database = [random.randint(1, 2**16) for _ in range(db_size)]

    def answerRequest(self, v, public_key):
        """
        v : request vector send by client - list of numbers
        public_key : tuple (n,g) of the client's public key
        Permits to return E(T[i]) while assuring the server doesn't now i, which means the exact request of the client
        """
        n, g = public_key
        n2 = n * n

        result = 1
        for enc_bit, value in zip(v, self.database):
            result = (result * gmpy2.powmod(enc_bit, value, n2)) % n2

        return result
