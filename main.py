
from  OEAP import *
from RSA import *

from Crypto.Math.Numbers import Integer


texto = 12355678
print("Original: ", texto)

texto_cifrado, d, n = cifraRSA(texto)
print("Cifrado: ", texto_cifrado)

texto = decifraRSA(texto_cifrado, d, n)
print("Decifrado: ", texto)

print("---------------------------------------------------")

# texto_cifrado, d, n = 
texto_cifrado = cifra_OAEP('5')

decifra_OAEP(texto_cifrado)

# print("Texto cifrado OAEP: ", texto_cifrado )

# print("Texto decifrado OAEP: ", decifraRSA(texto_cifrado, d, n))









