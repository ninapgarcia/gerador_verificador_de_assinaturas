# from cryptography.hazmat.primitives import hashes


# digest = hashes.Hash(hashes.SHAKE128(128))

# m = b"lalaland"
# print(m)
# digest.update(m)


# print(len(digest.finalize()))
import hashlib 

m = hashlib.sha3_224()

m.update(b"lalaland")

print(len(m.digest()))
print(m.digest_size)
print(m.hexdigest())
print(int(m.hexdigest(), 10))