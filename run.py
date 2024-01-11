from Crypto.Cipher import AES
import hashlib

def __pad(plain_text):
        number_of_bytes_to_pad = 128 - len(plain_text) % 128
        ascii_string = chr(number_of_bytes_to_pad)
        padding_str = number_of_bytes_to_pad * ascii_string
        padded_plain_text = plain_text + padding_str
        return padded_plain_text

def __unpad(plain_text):
    last_character = plain_text[len(plain_text) - 1:]
    bytes_to_remove = ord(last_character)
    return plain_text[:-bytes_to_remove]

def encrypt(key):

    # read data from file named plain_text.txt
    file = open("plain_text.txt", "r")
    plain_text = file.read()
    print("Plain Text from text: " + plain_text)

    # Generate Hash key
    hash = hashlib.sha256(key.encode()) 
    p = hash.digest()
    key = p
    iv = p.ljust(16)[:16]
    print("Encoding key is: ",key)

    # Converting the plain text to multiple of 128 bit
    plain_text = __pad(plain_text)

    # Encrypting the text
    cipher = AES.new(key, AES.MODE_CBC, iv)
    encrypted_text = cipher.encrypt(plain_text.encode())
    print(encrypted_text)

    # write the encrypted code to encrypted_text.txt file
    file = open("encrypted_text.txt","wb")
    file.write(encrypted_text)


def decrypt(key):
    # Read encrypted code from encrypted_text.txt
    file = open("encrypted_text.txt", "rb")
    encrypted_text = file.read()

    #Generate hash key
    hash=hashlib.sha256(key.encode()) 
    p = hash.digest()
    key = p
    iv = p.ljust(16)[:16]
    print("Encoding key is: ",key)

    aes = AES.new(key, AES.MODE_CBC, iv)
    plain_text = aes.decrypt(encrypted_text)
    plain_text = __unpad(plain_text).decode("utf-8")
    print("Decrypted Text: " + plain_text)



encrypt("mitu")
decrypt("mitu")