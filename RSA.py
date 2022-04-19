from ast import Return
from audioop import mul
import numpy as np
import random

from Crypto.Math.Numbers import Integer

# Inicializa gerador de números aleatorios do sistema operacional
systemRandom = random.SystemRandom()

def tem_divisor(valor, a):
    """
    Checa se um número é ou não primo

    Args:
        valor: número que será testado
        a: NÃO SEI EXPLICAR DIREITO, MAS É PROVAVELMENTE O NÚMERO DE INTERAÇÕES
    Returns:
        booleano que representa se número é ou não primo
    """

    exp = valor - 1

    while not exp & 1:
        exp >>= 1 # Bitwise right-shift

    if pow(a, exp, valor) == 1:
        return True

    while exp < valor - 1:
        if pow(a, exp, valor) == valor-1:
            return True

        exp <<= 1 # Bitwise left-shift 

def miller_rabin(valor, k = 40):
    for i in range(k):
        a = systemRandom.randrange(2, valor-1)
        
        if not tem_divisor(valor, a):
            return False
    
    return True


def gera_primo(tamanho_em_bits):
    while True:
        # O valor gerado é sempre um número ímpar
        valor = systemRandom.randrange(1 << tamanho_em_bits-1 , 1 << tamanho_em_bits) + 1
        
        # Testa se valor gerado é de fato um primo
        if(miller_rabin(valor)):
            return valor

def gera_p_q():
    # p = 104717
    # q = 104729
    p = 8669
    q = 7727
    # p = 7
    # q = 5
    p = gera_primo(1024)
    q = gera_primo(1024)

    return p,q 


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
    
    p, q = gera_p_q()
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