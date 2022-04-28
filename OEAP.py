
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

from colors import printBlue, printGreen



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

def bits_to_string(string_bits):
    s_list = [string_bits[i:i+8] for i in range(0, len(string_bits), 8)]
    int_list = [int(x, 2) for x in s_list]
    return "".join(chr(element) for element in int_list)

def padding(texto):
    string_bits = string_to_bits(texto)
    m = string_bits.rjust(BITS_M, '0') #nao sei bem se isso faz sentido mas acho que faz
    return m

def gera_aleatorio():
    return random.getrandbits(BITS_K)

def converte_bit_string_to_int(bitstring):
    return int(bitstring, 2)

def converte_int_to_bit_string(num, bit_len=BITS_M):
    return BitArray(uint=num, length=bit_len).bin

# Inicio > Peguei essas funções prontas do WIKIPEDIA!!!!!!!!!!!!!!
def i2osp(integer: int, size: int = 4) -> str:
    return b"".join([chr((integer >> (8 * i)) & 0xFF).encode() for i in reversed(range(size))])

def mgf1(input_str: bytes, length: int, hash_func=hashlib.sha3) -> str: # Não testei com SHA3 ainda ...
    """Mask generation function."""
    counter = 0
    output = b""
    while len(output) < length:
        C = i2osp(counter, 4)
        output += hash_func(input_str + C).digest()
        counter += 1
    return output[:length]
# Final > Peguei essas funções prontas do WIKIPEDIA!!!!!!!!!!!!!!

def G(r: int):
    r_bytes = str(r).encode()
    r_masked_bytes = mgf1(r_bytes, BITS_M//8)
    r_masked_int = int.from_bytes(r_masked_bytes, 'big')
    return r_masked_int

def H(P1: int):
    P1_bytes = P1.to_bytes(BITS_M//8, 'big')
    P1_masked = mgf1(P1_bytes, BITS_K//8)
    P1_masked_int = int.from_bytes(P1_masked, 'big')
    return P1_masked_int

# agora precisa fazer as funcoes G e H q nao entendi como sao 
def cifra_OAEP(texto):
    m = padding(texto)

    print("Inicial: ", m)

    r = gera_aleatorio()

    print("R: ", r)

    # Calculando P1 
    P1 = converte_bit_string_to_int(m) ^ G(r)

    P2 = r ^ H(P1) # P1_masked_int

    # Se não for no formato de bits ele quebra na outra parte kkkry -> Isso deve dar uim depois
    P = converte_int_to_bit_string(P1, BITS_M) + converte_int_to_bit_string(P2, BITS_K)

    P_int = int(P, 2)
    printBlue([P_int])
    return cifraRSA(P_int)
    
def decifra_OAEP(texto_cifrado,d, n):
    texto_decifradoRSA = decifraRSA(texto_cifrado, d, n)
    texto_decifradoRSA_bits =  converte_int_to_bit_string(texto_decifradoRSA, BITS_M+BITS_K)

    P1_int = converte_bit_string_to_int(texto_decifradoRSA_bits[:-BITS_K])
    P2_int = converte_bit_string_to_int(texto_decifradoRSA_bits[len(texto_decifradoRSA_bits)-BITS_K:])

    r = H(P1_int) ^ P2_int

    texto_decifrado = P1_int ^ G(r)

    print("Final: ", converte_int_to_bit_string(texto_decifrado))

    return bits_to_string(converte_int_to_bit_string(texto_decifrado))
    # Tem que tirar o padding agora -> tô dúvida como fazer isso
    # Tipo, que valores a gente pode usar pra fazer isso





