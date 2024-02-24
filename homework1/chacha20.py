import argparse

from Crypto.Cipher import ChaCha20

KEYFILE = "key.txt"
PUBFILE = "decryption.txt"


def main(action: str, i_key: str, f_file: str, d_dir: str):
    with open(f_file, "rb") as f:
        plaintext = f.read()

    try:
        key = bytes.fromhex(i_key)
    except:
        print('key is not a hexadecimal string')
        return 1
    if(len(key)!= 32):
        print('key lenth must be 32 bytes')
        return 1

    if action == "encrypt":
        with open(PUBFILE, "w") as nf:
            nf.write("")
        for i in range(5):
            cipher = ChaCha20.new(key=key)
            msg = cipher.encrypt(plaintext)
            with open("{}/ct-{}.bin".format(d_dir, i), "wb") as ctf:
                ctf.write(msg)
            nonce = bytes.hex(cipher.nonce)
            with open(PUBFILE, "a") as nf:
                nf.write(nonce)
                nf.write("\n")
            

    if action == "decrypt":
        with open(PUBFILE, "r") as nf:
            for i in range(5):
                nonce_text = nf.readline()
                nonce = bytes.fromhex(nonce_text)
                with open("{}/ct-{}.bin".format(d_dir, i), "rb") as ctf:
                    ciphertext = ctf.read()
                    cipher = ChaCha20.new(key=key, nonce=nonce)
                    decrypted = cipher.decrypt(ciphertext)
                    

            assert plaintext == decrypted  # adjust the type if necessary


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["encrypt", "decrypt"],
                        help="the action to perform")
    parser.add_argument("key", help="the secret key")
    parser.add_argument("file", help="the file to encrypt/verify against")
    parser.add_argument("dir", help="the directory of ciphertexts")

    args = parser.parse_args()
    main(args.action, args.key, args.file, args.dir)
