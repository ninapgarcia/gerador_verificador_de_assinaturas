
import random
import string 
import numpy as np

# LINK MT MT IMPORTANTE:
# https://github.com/boppreh/aes/blob/master/aes.py

"""
1. gerar a chave
    - 128 bits -> 10 rounds
    - 192 bits -> 12 rounds
    - 256 bits -> 14 rounds


2. separar a mensagem em blocos de 128 bits - 16 bytes
    [b0  b4  b8  b12]
    [b1  b5  b9  b13]
    [b2  b6  b10 b14]
    [b3  b7  b11 b15]

3. expansão da chave usando key schedule ?

4. XOR da chave com a mensagem

5. byte substitution -> usando SBOX

6. row shift

7. mix columns -> multiplica cada coluna por essa matriz
    [2 3 1 1]
    [1 2 3 1]
    [1 1 2 3]
    [3 1 1 2]

8. expansao da chave

9. Xor da chave com a mensagem

ROUND: 3 ao 9 -> repetir de acordo com a quantidade de rounds
       o último round nao tem a etapa 7. (mix columns)



- DIVISAO DA MENSAGEM EM BLOCOS

-> a mensagem deve ser dividida em blocos de 128 bits
-> se a ultima n tiver 16 byter faz um padding acho 
-> vamos ter um nonce e um contador tambem (o contador vai contando os blocos)
-> ainda n sei o que fazer com isso 

- AINDA TEM A PARTE DO MODO CTR
 -> nao tenho ctz se entendi bem 
 -> eu entendi a msm coisa q o mateusinho mas n faz sentido pra mim 
 -> u vou usar o AES para cifrar o nonce+contador (128bits, 64 de cada) e depois de 
    tudo eu faco xor do resultado com a o primeiro bloco da msg
-> incrementa o contador e vai repetindo isso pra cada bloco

"""

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

# usado na expasao da chave
RCON = (
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40,
    0x80, 0x1B, 0x36, 0x6C, 0xD8, 0xAB, 0x4D, 0x9A,
    0x2F, 0x5E, 0xBC, 0x63, 0xC6, 0x97, 0x35, 0x6A,
    0xD4, 0xB3, 0x7D, 0xFA, 0xEF, 0xC5, 0x91, 0x39,
)

def gera_chave():
    #talvez seja so qualquer coisa segundo o mateusinho
    # vamo usar 128 bits pq n sei usar as outras
    return ''.join(random.choices(string.ascii_letters + string.digits, k=16))


def msg_padding(msg):
    # msg já é passada encoded
    if len(msg) % 16 != 0:
        padding_len = 16 - (len(msg) % 16)
        padding = bytes([padding_len] * padding_len)
        return msg + padding

def msg_em_blocos(message):
    # divide a msg em blocos de 16 bytes
    blocos = [message[i:i+16] for i in range(0, len(message), 16)]
    return blocos

def vetor_para_matriz(msg):
    # transforma o vetor de 16 bytes em uma matriz 4x4
    # nao tenho ctz absoluta disso
    bloco_vetores = [list(msg[i:i+4]) for i in range(0, len(msg), 4)]
    bloco_matriz = np.zeros((4, 4))
    bloco_matriz[:, 0] = bloco_vetores[0]
    bloco_matriz[:, 1] = bloco_vetores[1]
    bloco_matriz[:, 2] = bloco_vetores[2]
    bloco_matriz[:, 3] = bloco_vetores[3]
    return bloco_matriz.astype(int)

def coluna_shift(coluna):
    # usada na expansao da chave
    aux = coluna[0]
    coluna[0] = coluna[1]
    coluna[1] = coluna[2]
    coluna[2] = coluna[3]
    coluna[3] = aux
    return coluna

def byte_substituicao(coluna):
    sub_coluna = [SBOX[b] for b in coluna]
    return sub_coluna

def add_rcon(coluna, round):
    coluna[0] = coluna[0] ^ RCON[round]
    return coluna
    
def xor_colunas(coluna1, coluna2):
    colunas_xor = []
    for i in range(len(coluna1)):
        colunas_xor.append(coluna1[i] ^ coluna2[i])
    return colunas_xor

def expansao_chave(chave, round):
    #realiza a expansao da chave

    chave_expandida = np.zeros((4, 4))
    ultima_coluna = chave[:, 3]
    # print('\nULTIMA COLUNA: ', ultima_coluna_chave)

    coluna_shifted = coluna_shift(ultima_coluna)
    # print('\nSHIFT NA COLUNA: ', coluna_shifted)

    sub_coluna = byte_substituicao(coluna_shifted)
    # print('\nCOLUNA SBOX: ', sub_coluna)

    coluna_rcon = add_rcon(sub_coluna, round)
    # print('COLUNA RCON: ', coluna_rcon)

    # xor das colunas
    coluna0 = xor_colunas(coluna_rcon, chave[:, 0])
    coluna1 = xor_colunas(coluna0, chave[:, 1])
    coluna2 = xor_colunas(coluna1, chave[:, 2])
    coluna3 = xor_colunas(coluna2,  chave[:, 3])

    chave_expandida[:, 0] = coluna0
    chave_expandida[:, 1] = coluna1
    chave_expandida[:, 2] = coluna2
    chave_expandida[:, 3] = coluna3

    return chave_expandida.astype(int)

def xor_matrizes(matriz1, matriz2):
    # xor de duas matrizes elemento a elemento
    result = np.zeros((4, 4))
    for i in range(4):
        for j in range(4):
            result[i][j] = matriz1[i][j] ^ matriz2[i][j]
            
    return result.astype(int)

def row_shift(matriz):
    #linha 2
    matriz[1][0], matriz[1][1], matriz[1][2], matriz[1][3] = matriz[1][1], matriz[1][2], matriz[1][3], matriz[1][0]
    #linha 3
    matriz[2][0], matriz[2][1], matriz[2][2], matriz[2][3] = matriz[2][1], matriz[2][2], matriz[2][3], matriz[2][0]
    #linha 4
    matriz[3][0], matriz[3][1], matriz[3][2], matriz[3][3] = matriz[3][1], matriz[3][2], matriz[3][3], matriz[3][0]

    return matriz.astype(int)

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
# ---------------------------------------------------------------------



# por enquanto so usei pra visualizacao mas acho q vai ser util
def int_para_hex(lista):
    lista_hex = []
    for elem in lista:
        lista_hex.append(hex(elem))
    return lista_hex



def cifra_AES(msg):

    # manipulacao da msg -----------------------------------
    mas_c_padding = msg_padding(msg.encode())
    print('\nMENSAGEM COM PADDING: ', mas_c_padding)

    blocos = msg_em_blocos(mas_c_padding)
    print('\nMENSAGEM EM BLOCOS DE 16 BYTES: ', blocos)

    # AQUI TO CONSIDERANDO QUE SO TEM UM BLOCO
    for bloco in blocos:
        bloco1_msg = vetor_para_matriz(bloco)
        print('\nMATRIZ: ', bloco1_msg)
    # end - manipulacao da msg -------------------------------
    

    # manipulacao chave -----------------------------------
    chave = gera_chave()
    print('CHAVE: ', chave)

    chave_matriz = vetor_para_matriz(chave.encode())

    # end - manipulacao chave -------------------------------

    chave_expandida = expansao_chave(chave_matriz, 0) # nao sei bem se aqui comeca do 0 ou 1
    msg_xor_chave = xor_matrizes(bloco1_msg, chave_expandida)

    # AQUI COMECA OS ROUNDS
    for round in range(1, 9): 


        msg_subs = np.zeros((4, 4))
        for i in range(4):
            msg_subs[i] = byte_substituicao(msg_xor_chave[i])

        msg_shift = row_shift(msg_subs.astype(int))

        msg_mix = mix_colunas(msg_shift)

        chave_expandida = expansao_chave(chave_matriz, round)
        msg_xor_chave = xor_matrizes(msg_mix, chave_expandida)


    # ULTIMO ROUND NAO TEM MIX COLUMNS
    msg_subs = np.zeros((4, 4))
    for i in range(4):
        msg_subs[i] = byte_substituicao(msg_xor_chave[i])

    msg_shift = row_shift(msg_subs.astype(int))

    chave_expandida = expansao_chave(chave_matriz, round)
    msg_xor_chave = xor_matrizes(msg_shift, chave_expandida)

    return msg_xor_chave


# TESTES -------------------------------------------------------------------

# IMPORTANTE 
# cada vetor printado representa uma COLUNA  e nao uma lINHA 

# chave = gera_chave()
# print('CHAVE: ', chave)

# msg = "marina bla bla "
# mas_c_padding = msg_padding(msg.encode())
# print('\nMENSAGEM COM PADDING: ', mas_c_padding)

# blocos = msg_em_blocos(mas_c_padding)
# print('\nMENSAGEM EM BLOCOS DE 16 BYTES: ', blocos)

# for bloco in blocos:
#     bloco1_msg = vetor_para_matriz(bloco)
#     print('\nMATRIZ: ', bloco1_msg)

# chave_matriz = vetor_para_matriz(chave.encode())
# print('\nCHAVE EM MATRIZ: ', chave_matriz)

# chave_expandida = expansao_chave(chave_matriz, 1)
# print('\nCHAVE EXPANDIDA: ', chave_expandida)


# msg_xor_chave = xor_matrizes(bloco1_msg, chave_expandida)
# print('\nMSG XOR CHAVE: ', msg_xor_chave)

# msg_subs = np.zeros((4, 4))
# for i in range(4):
#     msg_subs[i] = byte_substituicao(msg_xor_chave[i])
# print('\nSUBSTITUICAO BYTE: ', msg_subs)


# msg_shift = row_shift(msg_subs.astype(int))
# print('\nROW SHIFT: ', msg_shift)

# msg_mix = mix_colunas(msg_shift)
# print('\nMIX COLUNAS: ', msg_mix)


cifrada = cifra_AES("marina linda")
print('\nCIFRADA: ', cifrada)