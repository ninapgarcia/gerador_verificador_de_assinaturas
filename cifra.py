

def cifra(texto, e, n):
    texto_cifrado = pow(texto, e, n)
    return texto_cifrado

def decifra(texto_cifrado, d, n):
    texto = pow(texto_cifrado, d, n)
    return texto
