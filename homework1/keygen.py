from Crypto.Random import get_random_bytes

key_bytes = get_random_bytes(32)
key_text = bytes.hex(key_bytes)

with open("./key.txt", "w") as f:
    f.write(key_text)