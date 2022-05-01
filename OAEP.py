
from sys import getsizeof
import random
from xml.etree.ElementTree import tostring
from bitstring import BitStream, BitArray

from RSA import *
import hashlib
from binascii import hexlify
from colors import printBlue, printGreen


# numero de bits m e k
BITS_M = 512
BITS_K = 32

def calcula_bits(texto):
    num_bits = len(texto) * 8 
    return num_bits

def string_to_bits(texto):
    string_bits = ''.join(format(ord(i), '08b') for i in texto)
    return string_bits

def bits_to_string(string_bits):
    s_list = [string_bits[i:i+8] for i in range(0, len(string_bits), 8)]
    int_list = [int(x, 2) for x in s_list]
    string = "".join(chr(element) for element in int_list)

    string_final = ""
    for x in string:
        if ord(x) > 0:
            string_final += x
    return string_final

def padding(texto):
    string_bits = string_to_bits(texto)
    m = string_bits.rjust(BITS_M, '0') 
    return m

def gera_aleatorio():
    return random.getrandbits(BITS_K)

def converte_bit_string_to_int(bitstring):
    return int(bitstring, 2)

def converte_int_to_bit_string(num, bit_len=BITS_M):
    return BitArray(uint=num, length=bit_len).bin

# https://en.wikipedia.org/wiki/Mask_generation_function#:~:text=4%20References-,Definition,bounds%20are%20generally%20very%20large.
def i2osp(integer: int, size: int = 4) -> str:
    return b"".join([chr((integer >> (8 * i)) & 0xFF).encode() for i in reversed(range(size))])

def mgf1(input_str: bytes, length: int, hash_func=hashlib.sha1) -> str: # Não testei com SHA3 ainda ...
    counter = 0
    output = b""
    while len(output) < length:
        C = i2osp(counter, 4)
        output += hash_func(input_str + C).digest()
        counter += 1
    return output[:length]
# -----------------------------------------------------------

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

def cifra_OAEP(texto, e, n):
    m = padding(texto)
    # print("Inicial: ", m)

    r = gera_aleatorio()
    # print("R: ", r)

    # Calculando P1 
    P1 = converte_bit_string_to_int(m) ^ G(r)

    P2 = r ^ H(P1) # P1_masked_int

    # Se não for no formato de bits ele quebra na outra parte kkkry -> Isso deve dar uim depois
    P = converte_int_to_bit_string(P1, BITS_M) + converte_int_to_bit_string(P2, BITS_K)

    P_int = int(P, 2)
    # printBlue([P_int])
    return cifraRSA(P_int, e, n)
    
def decifra_OAEP(texto_cifrado,d, n):
    texto_decifradoRSA = decifraRSA(texto_cifrado, d, n)
    texto_decifradoRSA_bits =  converte_int_to_bit_string(texto_decifradoRSA, BITS_M+BITS_K)

    P1_int = converte_bit_string_to_int(texto_decifradoRSA_bits[:-BITS_K])
    P2_int = converte_bit_string_to_int(texto_decifradoRSA_bits[len(texto_decifradoRSA_bits)-BITS_K:])

    r = H(P1_int) ^ P2_int

    texto_decifrado = P1_int ^ G(r)

    return bits_to_string(converte_int_to_bit_string(texto_decifrado))






