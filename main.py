
from  cifraOEAP import *

from Crypto.Math.Numbers import Integer


texto = 27
print("Original: ", texto)

texto_cifrado, d, n = cifraRSA(texto)
print("Cifrado: ", texto_cifrado)

texto = decifraRSA(texto_cifrado, d, n)
print("Decifrado: ", texto)

print("---------------------------------------------------")

texto_cifrado, d, n = cifra_OAEP('5')

print("Texto cifrado OAEP: ", texto_cifrado )

print("Texto decifrado OAEP: ", decifraRSA(texto_cifrado, d, n))








