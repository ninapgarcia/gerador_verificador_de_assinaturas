# from  OEAP import *
# from RSA import *
from colors import *
from AES import *

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


# chave = [ 
#     ["0x2B", "0x28", "0xAB", "0x09"],
#     ["0x7E", "0xAE", "0xF7", "0xCF"],
#     ["0x15", "0xD2", "0x15", "0x4F"], 
#     ["0x16", "0xA6", "0x88", "0x3C"],
# ]

# np_chave = np.array(chave, dtype=str)
# np_chave = list(np_chave.flatten())
# to_int = lambda x: int(x,16)
# chave_int = np.array(list(map(to_int, np_chave)), dtype=np.int64)
# chave_int = np.reshape(chave_int, (4,4))
# print(chave_int)

# expandido = expansao_chave(chave_int)

# expandido = list(expandido.flatten())
# to_hex = lambda x: hex(x)

# expandido = np.array(list(map(to_hex, expandido)), dtype=str)
# expandido = np.reshape(expandido, (11, 4,4))

# print(expandido)

nonce = gera_nonce().encode()
print('NONCE: ', nonce)
contador = pad_contador(1).encode()
print('CONTADOR: ', contador)

nonce_contador = nonce_e_contador(nonce, contador)
print('NONCE + CONTADOR: ', nonce_contador)



print("\n-----------------------------------------------------------")

cifrada, chave_matriz = cifra_AES(nonce_contador)

print('\nCIFRADA: \n', cifrada)

decifrada = decifra_AES(cifrada, chave_matriz)

print('\nDECIFRADA: \n', decifrada)