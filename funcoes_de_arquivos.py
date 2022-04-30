import base64


def le_arquivo(endereco_arquivo:str):
    in_file = open(endereco_arquivo, "rb") # opening for [r]eading as [b]inary
    msg = in_file.read() # if you only wanted to read 512 bytes, do .read(512)
    msg = base64.b64encode(msg).decode()
    in_file.close()
    return msg

def escreve_arquivo(msg, endereco_arquivo):
    msg = base64.b64decode(msg)
    out_file = open(endereco_arquivo, "wb") # open for [w]riting as [b]inary
    out_file.write(msg)
    out_file.close()