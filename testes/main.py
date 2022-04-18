import base64
import rsa
import asn1

if __name__ == '__main__':
    e = 0x010001
    p = 0xCAA8F25E146F81FB0C31FB9FC98C5A4EDB25829EAA97B1B07C0761FE4E185D9EB886A8EC478A4BCCBF43A2AB3300A972074B1BACF1BEB731C1C096F9573A02D9
    q = 0xB0A1DD2EAB28ED07BE20658BF6D0FAA0CF395352746AB256A251F95AAA558E0C575866719821815A64F4DE0BE62E89D2F5E99805AFB1596C2755CCB96C4D9C63

    pub_key, prv_key = rsa.keygen(p, q, e)
    pub_pem, prv_pem = asn1.create_key_pair(p, q, e)
    print('Private key is:')
    print(prv_pem)

    cipher_text = rsa.encrypt_oaep('hello world!'.encode('ascii'), pub_key)
    print('RSA-OAEP Encrypted text is:')
    print(base64.encodestring(cipher_text).decode('ascii'))

    print('RSA-OAEP Decrypted text is:')
    plain_text = rsa.decrypt_oaep(cipher_text, prv_key)
    print(plain_text.decode('ascii'))
    print()

    cipher_text = rsa.encrypt_raw('hello world!'.encode('ascii'), pub_key)
    print('RSA-RAW Encrypted text is:')
    print(base64.encodestring(cipher_text).decode('ascii'))

    print('RSA-RAW Decrypted text is:')
    plain_text = rsa.decrypt_raw(cipher_text, prv_key)
    print(plain_text.decode('ascii'))