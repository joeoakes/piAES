
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad

#Encrypt the payload using AES
# keyAES = get_random_bytes(32)
keyAES = b"keykeykeykeykeykeykeykeykeykeyke"
print("Encrypting JSON payload using AES Cipher Block Chaining")
cipher = AES.new(keyAES, AES.MODE_CBC)
message = "Come over here Waston"
plaintext = message.encode('utf-8')
ct_bytes = cipher.encrypt(pad(plaintext, AES.block_size))
initializationVector = cipher.iv

# Decrypt the payload using AES
# key = get_random_bytes(32)
keyAES = b"keykeykeykeykeykeykeykeykeykeyke"
print("Decrypting JSON payload using AES Cipher Block Chaining")
cipher = AES.new(keyAES, AES.MODE_CBC, initializationVector)
plaintext = unpad(cipher.decrypt(ct_bytes), AES.block_size)
print("The message was: ", plaintext)