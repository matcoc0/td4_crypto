from paillier import Paillier
import gmpy2

class Client:
    def __init__(self, bits):
        self.paillier = Paillier(bits)

    def request(self, db_size, index):
        """
        Crée un vecteur chiffré v où seul l'élément à l'index donné est E(1), les autres E(0).
        Retourne (v, public_key) pour envoi au serveur.
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
