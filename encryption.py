import os
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


KEY_FILE = "secret.key"


def load_key():

    if not os.path.exists(KEY_FILE):

        key = AESGCM.generate_key(
            bit_length=256
        )

        with open(KEY_FILE,"wb") as f:
            f.write(key)

    else:

        with open(KEY_FILE,"rb") as f:
            key=f.read()


    return key



def encrypt_file(input_file, output_file):

    key = load_key()

    aes = AESGCM(key)


    nonce = os.urandom(12)


    with open(input_file,"rb") as f:

        data=f.read()



    encrypted = aes.encrypt(
        nonce,
        data,
        None
    )


    with open(output_file,"wb") as f:

        f.write(
            nonce + encrypted
        )


    return True




def decrypt_file(input_file, output_file):

    key = load_key()

    aes = AESGCM(key)


    with open(input_file,"rb") as f:

        data=f.read()



    nonce=data[:12]

    encrypted=data[12:]



    decrypted = aes.decrypt(
        nonce,
        encrypted,
        None
    )



    with open(output_file,"wb") as f:

        f.write(decrypted)



    return True