from  OAEP import *
from RSA import *
from colors import *
from AES import *
import hashlib
import base64

in_file = open("Relatorio1SC.pdf", "rb") # opening for [r]eading as [b]inary
msg = in_file.read() # if you only wanted to read 512 bytes, do .read(512)
msg = base64.b64encode(msg).decode()
in_file.close()

print('TYPE :', type(msg))

# print('MENSAGEM: ', msg)

print('\n\n---------------- GERADOR VERIFICADOR DE ASSINATURAS ----------------\n')

# msg = "msg muito braba e secreta maior ainda vai dar bom SUPER TEXTO GIGANTEW DE MAIS DE 128 BITS LALALALALALLA lsjfjsdlfjsjdf texto grande "


# Geração de chaves
print('\n -> Gerando chaves RSA ...')
chave_pub_e, chave_pub_n, chave_priv_d = geraChavesRSA()
print('\n -> Geradas as chaves (e, n) e (d, n)')

chave_k = gera_chave()
nonce = gera_nonce().encode()

print(CYAN, '\n CHAVE K = ', RESET, chave_k)

# print(CYAN, '\n MENSAGEM A SER CIFRADA:', RESET)
# print(' -> ', msg)

# Segundo bloco
print('\n -> Gerando hash da mensagem original ...')
msg_hash = hashlib.sha3_256(msg.encode()).hexdigest()
print('\n -> Cifrando hash com OAEP ...')
hash_cifrado = cifra_OAEP(msg_hash, chave_pub_e, chave_pub_n)

# Terceiro bloco
print('\n -> Cifrando mensagem com AES ...')
cifrada, chave = cifra(msg, nonce, chave_k)
print('\n -> Cifrando chave k com OAEP ...')
chave_k_cifrada = cifra_OAEP(chave_k, chave_pub_e, chave_pub_n)

# print(CYAN, '\n MENSAGEM CIFRADA (bytes):', RESET)
# print(' -> ', cifrada)

print('TYPE :', type(cifrada))


# Quarto bloco - A pessoa que recebeu as informações
print('\n -> Decifrando hash ...')
hash_decifrado = decifra_OAEP(hash_cifrado, chave_priv_d, chave_pub_n)

# Essa chave decifrada ainda esta com tamanho diferente mas ta funcionando k
print('\n -> Decifrando chave k ...')
chave_k_decifrada = decifra_OAEP(chave_k_cifrada, chave_priv_d, chave_pub_n)

print('\n -> Decifrando mensagem ...')
decifrada = decifra(cifrada, nonce, chave)
print('TYPE :', type(decifrada))


print('\n -> Gerando hash da mensagem decifrada ...')
msg_decifrada_hash = hashlib.sha3_256(decifrada.encode()).hexdigest()


print(CYAN, '\n HASH DA MENSAGEM ORIGINAL:  ', RESET, msg_decifrada_hash)
print(CYAN, 'HASH DA MENSAGEM DECIFRADA: ', RESET,  msg_hash)
if msg_decifrada_hash == msg_hash : print(GREEN, "\n\n -> SUCESSO !", RESET)


msg = decifrada.encode()
msg = base64.b64decode(msg)
out_file = open("out.pdf", "wb") # open for [w]riting as [b]inary
out_file.write(msg)
out_file.close()