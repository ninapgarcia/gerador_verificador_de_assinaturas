
from operator import inv
import random
import string 
import numpy as np
from sympy import block_collapse
from colors import *
import base64

# LINK MT MT IMPORTANTE:
# https://github.com/boppreh/aes/blob/master/aes.py


# para substituicao de bytes na cifracao
SBOX = (
    0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
    0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
    0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
    0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
    0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
    0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
    0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
    0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
    0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
    0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
    0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
    0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
    0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
    0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
    0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
    0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16,
)

# para a substituicao de byter na decifracao 
INV_SBOX = (
    0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
    0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB,
    0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E,
    0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25,
    0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92,
    0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84,
    0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06,
    0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B,
    0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73,
    0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E,
    0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B,
    0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4,
    0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F,
    0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF,
    0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D,
)

# usado na expansao da chave
RCON = (
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
    0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
    0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
    0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
)


def gera_nonce():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=8)) #64 bits
    # return random.randbytes(8)

def pad_contador(contador):
    contador = str(contador)
    while len(contador) < 8:
        contador = '0' + contador
    return contador

def nonce_e_contador(nonce, contador):
    return nonce + contador 

def gera_chave():
    return ''.join(random.choices(string.ascii_letters + string.digits, k=16)) #128 bits


def msg_padding(msg):
    # msg já é passada encoded
    if len(msg) % 16 != 0:
        padding_len = 16 - (len(msg) % 16)
        padding = bytes([0] * padding_len)
        # print("Padding: ", padding)
        return padding + msg
    return msg

def divide_blocos(message):
    # divide a msg em blocos de 16 bytes
    blocos = [message[i:i+16] for i in range(0, len(message), 16)]
    return blocos

def vetor_para_matriz(msg):
    # print("msg: ", msg)
    # transforma o vetor de 16 bytes em uma matriz 4x4 a cada 4 do vetor vira uma COLUNA
    bloco_vetores = [list(msg[i:i+4]) for i in range(0, len(msg), 4)]
    bloco_matriz = np.zeros((4, 4))
    bloco_matriz[:, 0] = bloco_vetores[0]
    bloco_matriz[:, 1] = bloco_vetores[1]
    bloco_matriz[:, 2] = bloco_vetores[2]
    bloco_matriz[:, 3] = bloco_vetores[3]

    # print("vt_pr_matriz: ", bloco_matriz)
    return bloco_matriz.astype(int)

def coluna_shift(coluna):
    aux = coluna[0]
    coluna[0] = coluna[1]
    coluna[1] = coluna[2]
    coluna[2] = coluna[3]
    coluna[3] = aux
    return coluna

def byte_substituicao(coluna):
    sub_coluna = [SBOX[b] for b in coluna]
    return sub_coluna

def inv_byte_substituicao(coluna):
    sub_coluna = [INV_SBOX[b] for b in coluna]
    return sub_coluna


def add_rcon(coluna, round):
    coluna[0] = coluna[0] ^ RCON[round]
    return coluna
    
def xor_colunas(coluna1, coluna2):
    colunas_xor = []
    for i in range(len(coluna1)):
        colunas_xor.append(coluna1[i] ^ coluna2[i])
    return colunas_xor

def expansao_chave(chave):
    #realiza a expansao da chave

    chave_expandida = np.zeros((11, 4, 4), dtype=np.int64)
    chave_expandida[0, :, :] = chave.copy()
    for i in range(1, 11):
        ultima_coluna = chave_expandida[i-1, :, 3].copy()

        coluna_shifted = coluna_shift(ultima_coluna)
        sub_coluna = byte_substituicao(coluna_shifted)
        coluna_rcon = add_rcon(sub_coluna, i)

        # xor das colunas
        coluna0 = xor_colunas(coluna_rcon, chave_expandida[i-1, :, 0])
        coluna1 = xor_colunas(coluna0, chave_expandida[i-1, :, 1])
        coluna2 = xor_colunas(coluna1, chave_expandida[i-1, :, 2])
        coluna3 = xor_colunas(coluna2,  chave_expandida[i-1, :, 3])

        chave_expandida[i, :, 0] = coluna0
        chave_expandida[i, :, 1] = coluna1
        chave_expandida[i, :, 2] = coluna2
        chave_expandida[i, :, 3] = coluna3

    return chave_expandida


def xor_matrizes(matriz1, matriz2):
    # xor de duas matrizes elemento a elemento
    result = np.zeros((4, 4))
    for i in range(4):
        for j in range(4):
            result[i][j] = matriz1[i][j] ^ matriz2[i][j]
    return result.astype(int)

def row_shift(matriz):
    
    nova_matriz = np.zeros((4,4), dtype=np.int64)

    nova_matriz[0] = np.roll(matriz[0], 0)
    nova_matriz[1] = np.roll(matriz[1], -1)
    nova_matriz[2] = np.roll(matriz[2], -2)
    nova_matriz[3] = np.roll(matriz[3], -3)

    return nova_matriz.astype(int)

def inv_row_shift(matriz):
    
    nova_matriz = np.zeros((4,4), dtype=np.int64)

    nova_matriz[0] = np.roll(matriz[0], 0)
    nova_matriz[1] = np.roll(matriz[1], 1)
    nova_matriz[2] = np.roll(matriz[2], 2)
    nova_matriz[3] = np.roll(matriz[3], 3)

    return nova_matriz.astype(int)

# essa parte eu peguei do git do homi 
# https://github.com/boppreh/aes/blob/master/aes.py
# ---------------------------------------------------------------------

# learned from http://cs.ucsb.edu/~koc/cs178/projects/JT/aes.c
xtime = lambda a: (((a << 1) ^ 0x1B) & 0xFF) if (a & 0x80) else (a << 1) # o q ta rolando aq??? K K

def mix_uma_coluna(coluna):
    # see Sec 4.1.2 in The Design of Rijndael
    t = coluna[0] ^ coluna[1] ^ coluna[2] ^ coluna[3]
    u = coluna[0]
    coluna[0] ^= t ^ xtime(coluna[0] ^ coluna[1])
    coluna[1] ^= t ^ xtime(coluna[1] ^ coluna[2])
    coluna[2] ^= t ^ xtime(coluna[2] ^ coluna[3])
    coluna[3] ^= t ^ xtime(coluna[3] ^ u)

def mix_colunas(matriz):
    for i in range(4):
        mix_uma_coluna(matriz[i])
    return matriz

def inv_mix_colunas(matriz):
    # see Sec 4.1.3 in The Design of Rijndael
    for i in range(4):
        u = xtime(xtime(matriz[i][0] ^ matriz[i][2]))
        v = xtime(xtime(matriz[i][1] ^ matriz[i][3]))
        matriz[i][0] ^= u
        matriz[i][1] ^= v
        matriz[i][2] ^= u
        matriz[i][3] ^= v
    
    return mix_colunas(matriz)



# por enquanto so usei pra visualizacao mas acho q vai ser util
def int_para_hex(lista):
    lista_hex = []
    for elem in lista:
        lista_hex.append(hex(elem))
    return lista_hex

def blocos_de_matriz_para_texto(matrizes):
    blocos = divide_blocos(matrizes)
    msg_texto = ""
    for x in range(len(blocos)):
        bloco_vetores = [list(blocos[x][i:i+4]) for i in range(0, len(blocos[x]), 4)]
        bytes_msg = bytes(list(np.matrix.flatten(np.array(bloco_vetores).T)))
        msg_texto += bytes_msg.decode()

    
    msg_texto_final = ""
    for x in msg_texto:
        if ord(x) > 0:
            msg_texto_final += x


            
    return msg_texto_final


def AES(nonce_contador, chave):

    blocos = divide_blocos(nonce_contador)

    # GAMBIARRA
    for bloco in blocos:
        bloco_nonce = vetor_para_matriz(bloco)    

    chave_matriz = vetor_para_matriz(chave.encode())

    # Add round key
    chave_expandida = expansao_chave(chave_matriz) 
    msg_xor_chave = xor_matrizes(bloco_nonce, chave_expandida[0, :, :])

    # AQUI COMECAM OS ROUNDS
    for round in range(1, 10): 
        # Sub Bytes
        msg_subs = np.zeros((4, 4))
        for i in range(4):
            msg_subs[i] = byte_substituicao(msg_xor_chave[i])
        # Shift rows
        msg_shift = row_shift(msg_subs.astype(int))
        # Mix columns
        msg_mix = mix_colunas(msg_shift)
        # Sub bytes
        msg_xor_chave = xor_matrizes(msg_mix, chave_expandida[round, :, :])

    # ULTIMO ROUND NAO TEM MIX COLUMNS
    msg_subs = np.zeros((4, 4))
    for i in range(4):
        msg_subs[i] = byte_substituicao(msg_xor_chave[i])
    # SHIFT
    msg_shift = row_shift(msg_subs.astype(int))
    # ADD ROUND KEY
    msg_xor_chave = xor_matrizes(msg_shift, chave_expandida[10, :, :])

    return msg_xor_chave


def cifra(msg, nonce, chave):

    msg_c_padding = msg_padding(msg.encode())

    #msg_c_padding = msg_padding(msg)
    print('\nMENSAGEM COM PADDING: ', msg_c_padding)

    msg_blocos = divide_blocos(msg_c_padding)
    print('\nMENSAGEM EM BLOCOS DE 16 BYTES: ', msg_blocos)

    msg_cifrada = []

    #percorre os blocos da mensagem
    for i in range(len(msg_blocos)):
        bloco_msg = vetor_para_matriz(msg_blocos[i])
        # print('\nMATRIZ BLOCO MSG: \n', bloco_msg)
    
        contador = pad_contador(i).encode()
        # print('CONTADOR: ', contador)

        nonce_contador = nonce_e_contador(nonce, contador)
        # print('NONCE + CONTADOR: ', nonce_contador)

        # print('\nCHAVE: ', chave)
        nonce_aes = AES(nonce_contador, chave)
        # print('\nNONCE AES CIFRA: \n', nonce_aes)


        bloco_cifrado = xor_matrizes(nonce_aes, bloco_msg) 
        # print('\nBLOCO CIFRADO: ', bloco_cifrado)

        bloco_cifrado = np.matrix.flatten(bloco_cifrado)
        # print('\nBLOCO CIFRADO VETOR: ', bloco_cifrado)

        msg_cifrada = np.append(msg_cifrada, bloco_cifrado)
        # print('\nMENSAGEM CIFRADA:  ', bloco_cifrado)


        
    return msg_cifrada.astype(int), chave




def decifra(msg_cifrada, nonce, chave):
    # print("\n DECIFRA  -----------------------------------------------------------")

    msg_blocos = divide_blocos(msg_cifrada)
    # print('\nMENSAGEM EM BLOCOS DE 16 BYTES: ', msg_blocos)

    msg_decifrada = []

    #percorre os blocos da mensagem
    for i in range(len(msg_blocos)):
        bloco_msg = msg_blocos[i].reshape((4, 4))
        # print('\nMATRIZ BLOCO MSG: \n', bloco_msg)
    
        contador = pad_contador(i).encode()
        # print('CONTADOR: ', contador)

        nonce_contador = nonce_e_contador(nonce, contador)
        # print('NONCE + CONTADOR: ', nonce_contador)

        # print('\nCHAVE: ', chave)
        nonce_aes = AES(nonce_contador, chave)
        # print('\nNONCE AES DECIFRA: \n', nonce_aes)

        bloco_decifrado = xor_matrizes(bloco_msg, nonce_aes) 
        # print('\nBLOCO DECIFRADO: ', bloco_decifrado)

        bloco_decifrado = np.matrix.flatten(bloco_decifrado)
        # print('\nBLOCO DECIFRADO VETOR: ', bloco_decifrado)

        msg_decifrada = np.append(msg_decifrada, bloco_decifrado)
    
    return blocos_de_matriz_para_texto(msg_decifrada.astype(int))



# def decifra_AES(msg_cifrada, chave_matriz):
#     # ADD ROUND KEY
#     count = 39

#     # print(count) # 39 
#     # printBlue(msg_cifrada)
#     count -=1


#     chave_expandida = expansao_chave(chave_matriz)
#     msg_xor_chave = xor_matrizes(msg_cifrada, chave_expandida[10, :, :])

#     # print(count) # 38
#     # printBlue(msg_xor_chave)
#     count -=1

#     for round in range(9,0,-1):
#         # INV SHIFT
#         inv_shift = inv_row_shift(msg_xor_chave)
        
#         # print(count) # 37
#         # printBlue(inv_shift)
#         count -=1
        
#         # INV SUB
#         inv_sub = np.zeros((4,4), dtype=np.int64)
#         for i in range(4):
#             inv_sub[i] = inv_byte_substituicao(inv_shift[i])
                
#         # print(count) # 36
#         # printBlue(inv_sub)
#         count -=1

#         # ADD ROUND KEY
#         # chave_expandida = expansao_chave(chave_matriz, round)
#         msg_xor_chave = xor_matrizes(inv_sub, chave_expandida[round, :, :])
        
#         # print(count) # 35
#         # printBlue(msg_xor_chave)
#         count -=1

#         # INV MIX COLUMNS
#         mix_msg = inv_mix_colunas(msg_xor_chave)

#         # print(count) # 34
#         # printBlue(mix_msg)
#         count -=1

#         msg_xor_chave = mix_msg.copy()
    
#     inv_shift = inv_row_shift(msg_xor_chave)
#     # print(count)
#     # printBlue(inv_shift)
#     count -=1

#     inv_sub = np.zeros((4,4), dtype=np.int64)
#     for i in range(4):
#         inv_sub[i] = inv_byte_substituicao(inv_shift[i])

#     # print(count)
#     # printBlue(inv_sub)
#     count -=1

#     # chave_expandida = expansao_chave(chave_matriz, 0)
#     msg_xor_chave = xor_matrizes(inv_sub, chave_expandida[0, :, :])

#     print(count)
#     printBlue(inv_sub)
#     count -=1


#     return msg_xor_chave

