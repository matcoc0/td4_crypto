from Client import Client
from server import Server

# parameters and initializatino
bits = 512
n_elements = 10
index_to_retrieve = 4
client = Client(bits)
server = Server(n_elements)

v, pk = client.request(n_elements, index_to_retrieve) # preparation of request of client 

response = server.answerRequest(v, pk) # answer of server

# Le client déchiffre la réponse
retrieved = client.decryptAnswer(response) # decrypting of answer

print("Asked index:", index_to_retrieve)
print("Expected value:", server.database[index_to_retrieve])
print("Real value:", retrieved)

assert retrieved == server.database[index_to_retrieve] # check that answer is good
print("Good answer!")
