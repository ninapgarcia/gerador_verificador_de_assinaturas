


def interacao_com_usuario():
    print(" Você deseja: ")
    print(" 1- Encriptar um texto.")
    print(" 2- Encriptar um arquivo.")
    print(" 3- Finalizar programa.")
    opcao_usuario = 0
    while opcao_usuario not in [1, 2, 3]:
        opcao_usuario = int(input(" "))
    return opcao_usuario

def pega_texto():
    return input("Digite a mensagem que você deseja cifrar: ")

def pega_arquivo():
    nome = input("Digite o nome do arquivo que você deseja cifrar: ")
    formato = input("Digite o formato do arquivo que você deseja cifrar: ")
    return nome, formato