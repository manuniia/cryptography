import argparse

from pwn import *
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

BLOCK_SIZE = AES.block_size


def pad_pkcs(msg: bytes, bl: int = BLOCK_SIZE) -> bytes:
    """Pad a message to a multiple of the block length following PKCS#7.

    :param msg: The message to pad
    :param bl: The block length
    :return: the padded message
    """
    msg_len = len(msg)
    remain = msg_len % bl

    if remain == 0 :
        return msg
    
    padding = bl - remain

    return msg.ljust(msg_len+padding, bytes([padding]))


def unpad_pkcs(padded: bytes, bl: int = BLOCK_SIZE) -> bytes:
    """Remove PKCS#7 message padding.

    :param padded: The padded message
    :param bl: The block length
    :return: the unpadded message
    """
    last = padded[-1]
    if last >= bl:
        return padded
    
    if padded.endswith(bytes([last]* last)):
        return padded[:len(padded) - last]
    
    return padded


def encrypt(msg: bytes, key: bytes, iv: bytes = None) -> bytes:
    """Encrypt a message in CBC mode.

    If the IV is not provided, generate a random IV.
    :param msg: The message to encrypt
    :param key: The encryption key
    :param iv: The IV used for encryption
    :return: the ciphertext with the IV as the first block
    """
    padded_msg = pad_pkcs(msg)
    vector = iv if iv != None else get_random_bytes(BLOCK_SIZE)
    aes = AES.new(key, AES.MODE_ECB)
    result = iv

    for i in range(0, len(padded_msg), BLOCK_SIZE):
        block = padded_msg[i:i+BLOCK_SIZE]
        encrypted_block = aes.encrypt(xor(block, vector))
        result += encrypted_block
        vector = encrypted_block

    return result


def decrypt(ct: bytes, key: bytes) -> bytes:
    """Decrypt a ciphertext in CBC mode.

    :param ct: The encrypted message
    :param key: The decryption key
    :return: the unpadded plaintext
    """
    vector = ct[0:BLOCK_SIZE]
    aes = AES.new(key, AES.MODE_ECB)
    result = b''

    for i in range(BLOCK_SIZE, len(ct), BLOCK_SIZE):
        encrypted_block = ct[i:i+BLOCK_SIZE]
        block = xor(aes.decrypt(encrypted_block), vector)
        result += block
        vector = encrypted_block

    return unpad_pkcs(result)



def encrypt_lib(msg: bytes, key: bytes, iv: bytes) -> bytes:
    """Encrypt a message using library CBC.

    :param msg: The message to encrypt
    :param key: The encryption key
    :param iv: The IV used for encryption
    :return: the ciphertext with the IV as the first block
    """
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    return iv + cipher.encrypt(pad_pkcs(msg))


def decrypt_lib(ct: bytes, key: bytes) -> bytes:
    """Decrypt a ciphertext using library CBC.

    :param ct: The encrypted message
    :param key: The decryption key
    :return: the unpadded plaintext
    """
    cipher = AES.new(key, AES.MODE_CBC)
    return unpad_pkcs(cipher.decrypt(ct)[BLOCK_SIZE:])


def main(i_key: str, i_msg: str, i_iv: str):
    try:
        key = bytes.fromhex(i_key)
    except:
        print('key is not a hexadecimal string')
        return 1
    if(len(key)!= 16 and len(key)!= 24 and len(key)!= 32):
        print('key lenth must be 16, 24 or 32 bytes')
        return 1
    
    try:
        msg = bytes.fromhex(i_msg)
    except:
        print('message is not a hexadecimal string')
        return 1
    
    try:
        iv = get_random_bytes(BLOCK_SIZE) if i_iv == None else bytes.fromhex(i_iv)
    except:
        print('key is not a hexadecimal string')
        return 1
    if(len(iv)!= BLOCK_SIZE):
        print('iv length must equal block size (16 bytes)')
        return 1

    ciphertext = encrypt(msg, key, iv)
    check_enc = encrypt_lib(msg, key, ciphertext[:BLOCK_SIZE])

    assert ciphertext == check_enc

    # Do not remove or modify the print statements.
    print("Key:", key.hex())
    print("PT :", msg.hex())
    print("IV :", ciphertext[:BLOCK_SIZE].hex())
    print("CT :", ciphertext[BLOCK_SIZE:].hex())

    decrypted = decrypt(ciphertext, key)
    check_dec = decrypt_lib(ciphertext, key)

    assert decrypted == check_dec
    assert decrypted == msg


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("key", help="the secret key")
    parser.add_argument("message", help="the message to encrypt")
    parser.add_argument("--iv", help="the initialisation vector (optional)")

    args = parser.parse_args()
    main(args.key, args.message, args.iv)

