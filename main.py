from chavesRSA import *
from  cifraOEAP import *

# p, q = gera_primos()
# print('p = ', p)
# print('q = ', q)

# n = calcula_n(p, q)
# print('n = ', n)

# z = calcula_z(p, q)
# print('z = ', z)

# e = calcula_e(z)
# print('e = ', e)

# d = calcula_d(e, z)
# print('d = ', d)


# texto = 27

# texto_cifrado = cifraRSA(texto, e, n)
# print(texto_cifrado)

# texto = decifraRSA(texto_cifrado, d, n)
# print(texto)


texto = 'marina'
print(calcula_bits(texto))
print(string_to_bits(texto))
m = padding(texto)

aleatorio = gera_aleatorio()
print(aleatorio)
bin_aleatorio = bin(aleatorio)[2:]
print(bin_aleatorio)
print(len(bin_aleatorio))







