from  OEAP import *
from RSA import *
from colors import *
from AES import *


msg = """
    msg muito braba e secreta
"""

# Para verificar se a mensagem é válida
msg_cifrada_RSA, d_msg, n_msg = cifra_OAEP(msg)

# Você quer mandar sua mensagem criptografada com o AES
msg_cifrada_AES, chave_matriz = cifra_AES_CTR(msg)

# Formato da matriz tinha que ser string, né ? 

# Criptografar a chave matriz com RSA in OEAP
chave_cifrada_RSA, d, n = cifraRSA(chave_matriz)

chave_decifrada = decifraRSA(chave_cifrada_RSA)

msg_decifrada = decifra_AES_CTR(msg_cifrada_AES, chave_decifrada)


