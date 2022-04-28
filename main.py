# from  OEAP import *
# from RSA import *
from colors import *
from AES import *
import numpy as np

# print(gera_primo(1024))

# texto = 12973183183831987398127319827319873981733
# print("Original: ", texto)

# texto_cifrado, d, n = cifraRSA(texto)
# print("Cifrado: ", texto_cifrado)

# texto = decifraRSA(texto_cifrado, d, n)
# print("Decifrado: ", texto)

# print("---------------------------------------------------")

# texto_original = '512348' 
# print(BLUE, "ORIGINAL: \t", RESET , texto_original)

# texto_cifrado, d, n = cifra_OAEP(texto_original)
# print(BLUE, "CIFRADO OEAP: \t", RESET, texto_cifrado)

# texto_decifrado = decifra_OAEP(texto_cifrado, d, n)
# print(BLUE, "FINAL: \t", RESET,texto_decifrado)


print("\n-----------------------------------------------------------")


nonce = gera_nonce().encode()
print('NONCE: ', nonce)

msg = "meu texto com 2 blocos"
print("\n-----------------------------------------------------------")

chave = gera_chave()
cifrada, chave, bloco_msg = cifra(msg, nonce, chave)
decifrada = decifra(cifrada, nonce, chave)

# cifrada = AES(nonce_contador, chave)

print("\n-----------------------------------------------------------")

print('\nMSG: \n', np.matrix.flatten(bloco_msg))
print('\nCIFRADA: \n', cifrada)
print('\nDECIFRADA BLOCOS: \n', decifrada)

# Tirar isso da main acho que vai pra dentro de decifra mesmo ...
blocos = divide_blocos(decifrada)
msg_texto_final = ""
for x in range(len(blocos)):
    bloco_vetores = [list(blocos[x][i:i+4]) for i in range(0, len(blocos[x]), 4)]
    msg_texto_final += bytes(list(np.matrix.flatten(np.array(bloco_vetores).T))).decode()
print("DECIFRADA TEXTO: ", msg_texto_final)