from cryptography.hazmat.primitives import hashes


digest = hashes.Hash(hashes.SHAKE128(128))

m = b"lalaland"
print(m)
digest.update(m)


print(len(digest.finalize()))