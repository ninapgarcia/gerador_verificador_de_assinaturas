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
print("Tamanho do texto em bits:\t", calcula_bits(texto))
print("Texto em bits:\t\t\t", string_to_bits(texto))

m = padding(texto)
print("Texto com padding:\t\t", m)

aleatorio = gera_aleatorio()
print(aleatorio)
bin_aleatorio = bin(aleatorio)[2:]
print(bin_aleatorio)
print(len(bin_aleatorio))

a = '1000100101'
b = '1000011000'

c = convert_bit_string_to_int(a) ^ convert_bit_string_to_int(b)

print('\n\n')
print(a)
print('^')
print(b)
print('=')
print(convert_int_to_bit_string(c))







