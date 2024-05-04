import des
from Crypto.Cipher import DES
from Crypto.Random import get_random_bytes
import time

def timed_print(action, start, end):
    print(f"{action} time: {(end - start)*1000} ms")

# ECM
key = des.DesKey(b"12345678")
plaintext = b"Lorem Ipsum dolores sit amet, consectetur adipiscing elit. Nullam auctor, nunc nec lacinia fermentum, nunc nunc fermentum nunc,"

print("ECM:")
encstart = time.time()
encrypted = key.encrypt(plaintext, padding=True)
encend = time.time()
timed_print("enc", encstart, encend)

decstart = time.time()
decrypted = key.decrypt(encrypted, padding=True)
decend = time.time()

timed_print("dec", decstart, decend)


if plaintext == decrypted:
    print("Decryption successful")

# CBC
key = des.DesKey(b"12345678")

print("CBC:")
encstart = time.time()
encrypted = key.encrypt(plaintext, padding=True, initial=b"87654321")
encend = time.time()
timed_print("enc", encstart, encend)

# create 1 bit error
#encrypted = bytearray(encrypted)
#encrypted[12] = encrypted[12] ^ 1
#encrypted = bytes(encrypted)

decstart = time.time()
decrypted = key.decrypt(encrypted, padding=True, initial=b"87654321")
decend = time.time()
timed_print("dec", decstart, decend)

#print(decrypted)

if plaintext == decrypted:
    print("Decryption successful")

# CFB (neue library da die alte CFB nicht unterstützt)
def pad(data):
    padding_length = 8 - (len(data) % 8)
    return data + bytes([padding_length] * padding_length)

def unpad(data):
    padding_length = data[-1]
    return data[:-padding_length]

def encrypt_cfb(des_key, iv, plaintext):
    cipher = DES.new(des_key, DES.MODE_CFB, iv)
    encrypted = cipher.encrypt(plaintext)
    return encrypted

def decrypt_cfb(des_key, iv, ciphertext):
    cipher = DES.new(des_key, DES.MODE_CFB, iv)
    decrypted = cipher.decrypt(ciphertext)
    return decrypted

key = b'12345678' 
iv = get_random_bytes(8) 

padded_plaintext = pad(plaintext)

print("CFB:")
encstart = time.time()
encrypted = encrypt_cfb(key, iv, padded_plaintext)
encend = time.time()
timed_print("enc", encstart, encend)

decstart = time.time()
decrypted = decrypt_cfb(key, iv, encrypted)
decend = time.time()

timed_print("dec", decstart, decend)

unpadded_decrypted = unpad(decrypted)
if plaintext == unpadded_decrypted:
    print("Decryption successful")

# CTR
def encrypt_ctr(des_key, nonce, plaintext):
    cipher = DES.new(des_key, DES.MODE_CTR, nonce=nonce)
    encrypted = cipher.encrypt(plaintext)
    return encrypted

def decrypt_ctr(des_key, nonce, ciphertext):
    cipher = DES.new(des_key, DES.MODE_CTR, nonce=nonce)
    decrypted = cipher.decrypt(ciphertext)
    return decrypted

key = b'12345678' 
nonce = get_random_bytes(4)

print("CTR:")
encstart = time.time()
encrypted = encrypt_ctr(key, nonce, plaintext)
encend = time.time()
timed_print("enc", encstart, encend)
decstart = time.time()
decrypted = decrypt_ctr(key, nonce, encrypted)
decend = time.time()
timed_print("dec", decstart, decend)

if plaintext == decrypted:
    print("Decryption successful")


# CFB mit anderen feeback values
def custom_encrypt_cfb(des_key, iv, plaintext, feedback_size):
    cipher = DES.new(des_key, DES.MODE_ECB)
    encrypted = b""
    prev_block = iv
    for i in range(0, len(plaintext), feedback_size // 8):
        block = plaintext[i:i + feedback_size // 8]
        cipher_output = cipher.encrypt(prev_block)
        encrypted_block = bytes(a ^ b for a, b in zip(cipher_output, block))
        encrypted += encrypted_block
        prev_block = (prev_block[feedback_size // 8:] + encrypted_block)[-len(prev_block):]
    return encrypted

def custom_decrypt_cfb(des_key, iv, ciphertext, feedback_size):
    cipher = DES.new(des_key, DES.MODE_ECB)
    decrypted = b""
    prev_block = iv
    for i in range(0, len(ciphertext), feedback_size // 8):
        block = ciphertext[i:i + feedback_size // 8]
        cipher_output = cipher.encrypt(prev_block)
        decrypted_block = bytes(a ^ b for a, b in zip(cipher_output, block))
        decrypted += decrypted_block
        prev_block = (prev_block[feedback_size // 8:] + block)[-len(prev_block):]
    return decrypted


key = b'12345678' 
iv = get_random_bytes(8)  

custom_feedback_size = 64

print("Custom CFB:")

encstart = time.time()
encrypted_data = custom_encrypt_cfb(key, iv, plaintext, custom_feedback_size)
encend = time.time()
timed_print("enc", encstart, encend)

decstart = time.time()
decrypted_data = custom_decrypt_cfb(key, iv, encrypted_data, custom_feedback_size)
decend = time.time()
timed_print("dec", decstart, decend)

if plaintext == decrypted_data:
    print("Decryption successful")
