from Client import Client
from server import Server

# Paramètres
bits = 512
n_elements = 10
index_to_retrieve = 4

# Initialisation
client = Client(bits)
server = Server(n_elements)

# Le client prépare la requête
v, pk = client.request(n_elements, index_to_retrieve)

# Le serveur répond
response = server.answerRequest(v, pk)

# Le client déchiffre la réponse
retrieved = client.decryptAnswer(response)

# Affichage
print("Index demandé:", index_to_retrieve)
print("Valeur attendue:", server.database[index_to_retrieve])
print("Valeur récupérée:", retrieved)

# Vérification
assert retrieved == server.database[index_to_retrieve]
print("Réponse correcte !")
