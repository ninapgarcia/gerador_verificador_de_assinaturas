from audioop import mul
import numpy as np

from Crypto.Math.Numbers import Integer

def gera_primos():
    # p = 104717
    # q = 104729
    p = 8669
    q = 7727
    # p = 7
    # q = 5
    return p, q


def calcula_n(p, q):
    return p*q


def calcula_z(p, q):
    return (p-1)*(q-1)


def calcula_e(z):
    cont = 2
    e = 0
    while cont < z:
        e = z - cont 
        gcd = np.gcd(e, z)
        if gcd == 1:
            return e

        cont += 1
    
    print('Não tem coprimo')
    return 0
    
        

def calcula_d(e, z):
    d = Integer(1)
    z = Integer(z)
    e = Integer(e)

    while d != z:
        if (e * d) % z == 1:
            return d
        d += 1
    print('Não tem inverso modular')
    return 0

def cifraRSA(texto):
    p, q = gera_primos()
    print('p = ', p)
    print('q = ', q)

    n = calcula_n(p, q)
    print('n = ', n)

    z = calcula_z(p, q)
    print('z = ', z)

    e = calcula_e(z)
    print('e = ', e)

    # d = calcula_d(e, z)
    d = 22322989
    print('d = ', d)
    

    texto_cifrado = pow(Integer(texto), Integer(e), Integer(n))

    return texto_cifrado, d, n

def decifraRSA(texto_cifrado, d, n):
    texto = pow(Integer(texto_cifrado), Integer(d), Integer(n))
    return texto