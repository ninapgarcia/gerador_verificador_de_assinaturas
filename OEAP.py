
from sys import getsizeof
import random
from xml.etree.ElementTree import tostring
from bitstring import BitStream, BitArray

# Acelerando :)
from Crypto.Math.Numbers import Integer

from cryptography.hazmat.primitives import hashes

from RSA import *

import base64

import hashlib

from binascii import hexlify



"""
Temos uma mensagem de menos de m bits
Passos para realizar a cifra

> padding para deixar a mensagem com m bits
  esse padding pelo que entendi é adicionar zeros no final até completar (M)

> gerar numero aleatório de k bits (r)

> operação XOR com M e G(r) - G transforma k bits em m bits
  isso gera P1

> operacao XOR com H(P1) e r - H transforma m bits em k bits
  isso gera P2

> Juntar P1 e P2 (só um append normal pelo q entendi) (P)

> Encriptar essa mensagem P usando RSA

"""


"""
Para decifrar:

> Decifrar com RSA (P)

> Separar P em P1 e P2 (primeiros m bits são P1 e ultimos k bits são P2 acho)

> Descobrir numero aleatorio r com P2 XOR H(P1)

> Operação XOR com P1 e G(r) vira M

> Tirar o padding

> Mensagem decifrada 

"""

# numero de bits m e k
BITS_M = 128
BITS_K = 32


def calcula_bits(texto):
    num_bits = len(texto) * 8 #pq cada char é um byte ne?
    return num_bits

def string_to_bits(texto):
    string_bits = ''.join(format(ord(i), '08b') for i in texto)
    return string_bits

def padding(texto):
    string_bits = string_to_bits(texto)
    m = string_bits.ljust(BITS_M, '0') #nao sei bem se isso faz sentido mas acho que faz
    return m

def gera_aleatorio():
    return random.getrandbits(BITS_K)

def convert_bit_string_to_int(bitstring):
    return int(bitstring, 2)

def convert_int_to_bit_string(num, bit_len=BITS_M):
    return BitArray(uint=num, length=bit_len).bin

# def G(r):
#     digest = hashes.Hash(hashes.SHAKE128(16))
#     digest.update(r)
#     return digest.finalize()

# def H(p1):
#     digest = hashes.Hash(hashes.SHAKE128(BITS_K)) 
#     digest.update(p1)
#     return digest.finalize()

# def string_xor(a, b):
#     return int(a) ^ int(b)

# def xor(m, G):
#     print(len(m))
#     print(m)
#     print(len(G))
#     G_str = [str(int(bin(g), 2)) for g in G]
#     G_bin = [string_to_bits(g) for g in G_str]
#     print("".join(G_bin))



def i2osp(integer: int, size: int = 4) -> str:
    return b"".join([chr((integer >> (8 * i)) & 0xFF).encode() for i in reversed(range(size))])

def mgf1(input_str: bytes, length: int, hash_func=hashlib.sha1) -> str:
    """Mask generation function."""
    counter = 0
    output = b""
    while len(output) < length:
        C = i2osp(counter, 4)
        output += hash_func(input_str + C).digest()
        counter += 1
    return output[:length]

    
    # return [aa^int(bb)) for aa, bb in zip(m, G)]


# agora precisa fazer as funcoes G e H q nao entendi como sao 
def cifra_OAEP(texto):

    m = padding(texto)
    r = gera_aleatorio()

    print("R: ", r)

    r_bits = str(r).encode()
    
    # Converte 
    # G - Converte para Hexadecimal
    r_masked = mgf1(r_bits, BITS_M//8)
    print("r_masked: ", r_masked)
    print("r_masked-LEN_bytes: ", len(r_masked))
    r_masked_int = int.from_bytes(r_masked, 'big')
    print("r_masked: ", r_masked_int)
    print("r_masked_len_bits:", len(convert_int_to_bit_string(r_masked_int)))
    G = r_masked_int

    print()

    # Calculando P1 
    P1 = convert_bit_string_to_int(m) ^ G
    print("P1: ", P1)
    print("P1_len_bits: ", len(convert_int_to_bit_string(P1)))
    print()


    P1_bytes = P1.to_bytes(BITS_M//8, 'big')
    print("P1_bytes: ", P1_bytes)
    print("P1_bytes_len: ", len(P1_bytes))
    P1_masked = mgf1(P1_bytes, BITS_K//8)
    print("P1_masked: ", P1_masked)
    print("P1_masked_len: ", len(P1_masked))

    P1_masked_int = int.from_bytes(P1_masked, 'big')
    print("P1_masked_int: ", P1_masked_int)
    print("P1_masked_len_bits: ", len(convert_int_to_bit_string(P1_masked_int, BITS_K)))

    P2 = r ^ P1_masked_int

    print()
    print("P1: ", P1)
    print("P2: ", P2)
    P = str(P1) + str(P2)
    print("P: ", P)

    # Não vai funcionar RSA pq o nosso só suporta numerozinhos
    # return cifraRSA(int(P))

    # calcular G(r)
    # ...








