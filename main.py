
from  OEAP import *
from RSA import *

from Crypto.Math.Numbers import Integer


# print(gera_primo(1024))

texto = 12973183183831987398127319827319873981733
print("Original: ", texto)

texto_cifrado, d, n = cifraRSA(texto)
print("Cifrado: ", texto_cifrado)

texto = decifraRSA(texto_cifrado, d, n)
print("Decifrado: ", texto)

# print("---------------------------------------------------")

# # texto_cifrado, d, n = 
# texto_cifrado = cifra_OAEP('5')


# print("---------------------------------------------------")

# decifra_OAEP(texto_cifrado)

# print("Texto cifrado OAEP: ", texto_cifrado )

# print("Texto decifrado OAEP: ", decifraRSA(texto_cifrado, d, n))









