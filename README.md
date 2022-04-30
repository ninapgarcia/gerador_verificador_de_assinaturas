# gerador_verificador_de_assinaturas

## Funcionamento 

### Geração de chaves
- São geradas as chaves públicas e privadas do RSA
- É gerada a chave K do AES
- É gerado o nonce do AES

### Cifração
- É feito o hash da mensagem
- Este hash é cifrado com OAEP.

- Usa-se o nonce + contador pra cifrar com o AES usando a chave K e então cada bloco gerado cifra cada bloco da mensagem.
- É cifrada a chave k com o OAEP.

### Valores enviados
- Hash o cifrado da mensagem
- A chave k cifrada.
- A mensagem cifrada.
- O nonce.

### Decifração e verificação 
- Decifração do hash
- Decifração da chave k com OAEP.
- Decifração da mensagem com a chave k e o nonce
- É feito o hash da mensagem descoberta.
- Os hash são comparados para checar se a mensagem foi corrompida.

## Compilação
- Necessário python 3.8+
- Necessária a instalação das bibliotecas:
    - Ver isso aqui

- Então basta rodar o comando no linux
```zsh
python3 main.py  
```
- Ou o comando no windows
```zsh 
python main.py  
```