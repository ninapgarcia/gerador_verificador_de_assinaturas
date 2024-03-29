from  OAEP import *
from RSA import *
from colors import *
from AES import *
import hashlib
from funcoes_de_arquivos import *
from interface import *


def main():
    print('\n\n---------------- GERADOR VERIFICADOR DE ASSINATURAS ----------------\n')
    opcao_usuario = interacao_com_usuario()
    msg = ""
    nome = ""
    formato = ""
    if(opcao_usuario== 3): return
    if(opcao_usuario== 2): 
        nome, formato = pega_arquivo()
        msg = le_arquivo(nome+formato)
    if(opcao_usuario== 1): msg = pega_texto()


    # Geração de chaves
    print('\n -> Gerando chaves RSA ...')
    chave_pub_e, chave_pub_n, chave_priv_d = geraChavesRSA()
    print('\n -> Geradas as chaves (e, n) e (d, n)')
    chave_k = gera_chave()
    nonce = gera_nonce().encode()
    print(CYAN, '\n CHAVE K = ', RESET, chave_k)

    # Segundo bloco
    print('\n -> Gerando hash da mensagem original ...')
    msg_hash = hashlib.sha3_256(msg.encode()).hexdigest()
    print('\n -> Cifrando hash com OAEP ...')
    hash_cifrado = cifra_OAEP(msg_hash, chave_pub_e, chave_pub_n)

    # Terceiro bloco
    print('\n -> Cifrando mensagem com AES ...')
    cifrada = cifra(msg, nonce, chave_k)
    print('\n -> Cifrando chave k com OAEP ...')
    chave_k_cifrada = cifra_OAEP(chave_k, chave_pub_e, chave_pub_n)
    
    print(RED, "Mensagem cifrada bytes: ", RESET, cifrada)
    if(opcao_usuario == 1): print(RED, "Mensagem cifrada texto: ", RESET)
    if(opcao_usuario == 1): print(converte_array_de_bytes_para_string(cifrada))
    if opcao_usuario == 2: escreve_arquivo(cifrada, nome + "Cifrado" + formato)

    # Quarto bloco - A pessoa que recebeu as informações
    print('\n -> Decifrando hash ...')
    hash_decifrado = decifra_OAEP(hash_cifrado, chave_priv_d, chave_pub_n)
    print('\n -> Decifrando chave k ...')
    chave_k_decifrada = decifra_OAEP(chave_k_cifrada, chave_priv_d, chave_pub_n)
    print('\n -> Decifrando mensagem ...')
    decifrada = decifra(cifrada, nonce, chave_k_decifrada)


    print('\n -> Gerando hash da mensagem decifrada ...')
    msg_decifrada_hash = hashlib.sha3_256(decifrada.encode()).hexdigest()

    # Comparação do hash decifrado com o hash da emnsagem decifrada
    if(opcao_usuario == 1): print(GREEN, "Mensagem decifrada: ", RESET, decifrada)
    print(CYAN, '\n HASH DA MENSAGEM ORIGINAL:  ', RESET, msg_decifrada_hash)
    print(CYAN, 'HASH DA MENSAGEM DECIFRADA: ', RESET,  hash_decifrado)
    if msg_decifrada_hash == msg_hash : print(GREEN, "\n -> Mensagem íntegra!", RESET)

    msg = decifrada.encode()
    if opcao_usuario == 2: escreve_arquivo(msg, nome + "Decifrado" + formato)


if __name__ == "__main__":
    main()