from  OAEP import *
from RSA import *
from colors import *
from AES import *
import hashlib

msg = """
    msg muito braba e secreta
"""

# Geração de chaves
chave_pub_e, chave_pub_n, chave_priv_d = geraChavesRSA()
chave_k = gera_chave()
print("ChaveK: ", chave_k)
nonce = gera_nonce().encode()

# Segundo bloco
msg_hash = hashlib.sha3_256(msg.encode()).hexdigest()
# hash = hashlib.sha3_256()
# hash.digest_size(8)
# hash.update(msg)
# msg_hash = hash.digest()

hash_cifrado = cifra_OAEP(msg_hash, chave_pub_e, chave_pub_n)

# Terceiro bloco
cifrada, chave = cifra(msg, nonce, chave_k)
print("Chave: ", chave)
print("chaveK: ", chave_k)
print("chaveType: ", len(chave))
print("chaveKlen: ", len(chave_k))

chave_k_cifrada = cifra_OAEP(chave_k, chave_pub_e, chave_pub_n)

# Quarto bloco - A pessoa que recebeu as informações
hash_decifrado = decifra_OAEP(hash_cifrado, chave_priv_d, chave_pub_n)
chave_k_decifrada = decifra_OAEP(chave_k_cifrada, chave_priv_d, chave_pub_n)

print("MsgCifrada: ", cifrada)
# print(len(cifrada))
print("ChaveKDecifrada: ", chave_k_decifrada)
print("chaveDecifradalen: ", len(chave_k_decifrada))
for x in chave_k_decifrada:
    print(x, end="")
decifrada = decifra(cifrada, nonce, chave)

# O mesmo problema que tava rolando com a chave, rola com a mensagem,
# apesar de parecerem iguais, elas tem tamanhos diferentes, logo
# o hash da decifrada vai ser totalmente diferente... aí acho que tá por 
# aí o caminho de encontrar o erro... ver prints abaixo \/
print("decifrada:", decifrada)
print(len(decifrada))
print(len(msg))
msg_decifrada_hash = hashlib.sha3_256(decifrada.encode()).hexdigest()


if msg_decifrada_hash == msg_hash : print("Sucesso")
print(msg_decifrada_hash)
print(msg_hash)
