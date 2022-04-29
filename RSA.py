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
    return pow(e, -1, z)

def geraChavesRSA(display=False):
    """
    Args:

    Returns:
        e: chave pública expoente
        n: chave pública multiplo de primos
        d: chave privada inverso multiplicativo
    """
    p, q = gera_p_q()
    if display: print('p = ', p)
    if display: print('q = ', q)

    n = calcula_n(p, q)
    if display: print('n = ', n)

    z = calcula_z(p, q)
    if display: print('z = ', z)

    e = calcula_e(z)
    if display: print('e = ', e)

    d = calcula_d(e, z)
    if display: print('d = ', d)
    
    return e, n, d

def cifraRSA(texto, e, n):
    texto_cifrado = pow(Integer(texto), Integer(e), Integer(n))
    return texto_cifrado

def decifraRSA(texto_cifrado, d, n):
    texto = pow(Integer(texto_cifrado), Integer(d), Integer(n))
    return texto