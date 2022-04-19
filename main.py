from  OEAP import *
from RSA import *
from colors import *
# print(gera_primo(1024))

# texto = 12973183183831987398127319827319873981733
# print("Original: ", texto)

# texto_cifrado, d, n = cifraRSA(texto)
# print("Cifrado: ", texto_cifrado)

# texto = decifraRSA(texto_cifrado, d, n)
# print("Decifrado: ", texto)

# print("---------------------------------------------------")

texto_original = '5' 
print(BLUE, "ORIGINAL: \t", RESET , texto_original)

texto_cifrado, d, n = cifra_OAEP(texto_original)
print(BLUE, "CIFRADO OEAP: \t", RESET, texto_cifrado)

texto_decifrado = decifra_OAEP(texto_cifrado, d, n)
print(BLUE, "FINAL: \t", RESET,texto_decifrado)



