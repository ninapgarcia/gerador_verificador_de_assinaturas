
from sys import getsizeof
import random
from bitstring import BitStream, BitArray

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
BITS_K = 16


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

# agora precisa fazer as funcoes G e H q nao entendi como sao 
def OEAP(texto):
    m = padding(texto)
    r = gera_aleatorio()
    # calcular G(r)

    # precisa transformar a string em bit tpo '0110' -> 0b0110
    # tpo os bits escritos na string em bits msm
    # nao sei fazer isso 


    # ...





def cifraRSA(texto, e, n):
    texto_cifrado = pow(texto, e, n)
    return texto_cifrado

def decifraRSA(texto_cifrado, d, n):
    texto = pow(texto_cifrado, d, n)
    return texto
