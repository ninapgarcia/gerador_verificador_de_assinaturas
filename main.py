from gerador_chaves import *
from  cifra import *

p, q = gera_primos()
print('p = ', p)
print('q = ', q)

n = calcula_n(p, q)
print('n = ', n)

z = calcula_z(p, q)
print('z = ', z)

e = calcula_e(z)
print('e = ', e)

d = calcula_d(e, z)
print('d = ', d)


texto = 27

texto_cifrado = cifra(texto, e, n)
print(texto_cifrado)

texto = decifra(texto_cifrado, d, n)
print(texto)





