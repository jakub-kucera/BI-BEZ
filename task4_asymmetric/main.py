# Author Jakub Kucera <kucerj56@fit.cvut.cz>
# Date  13.4.2021
import os
import sys
from argparse import ArgumentParser
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util import Padding

BUFFER_SIZE = 1024
BLOCK_SIZE = 16
BYTEORDER = 'little'
CYPHERS = {1: AES}
CYPHER_CODE_TO_LENGTH = {0: 128, 1: 256, 2: 384, 3: 512}
CYPHER_LENGTH_TO_CODE = dict([(length, code) for code, length in CYPHER_CODE_TO_LENGTH.items()])
CYPHER_MODES = {1: AES.MODE_CBC, 2: AES.MODE_CCM, 3: AES.MODE_CFB}


def encrypt_file(recipient_public_key: RSA.RsaKey, in_file_name: str, out_file_name: str):

    # opens destination file
    with open(out_file_name, mode="wb") as out_file:

        # loads recipients public rsa key from file
        # recipient_public_key = RSA.import_key(open(key_file_name).read())
        cipher_rsa = PKCS1_OAEP.new(recipient_public_key)

        # generates, encrypts session key and writes it to file
        session_key = get_random_bytes(BLOCK_SIZE)
        encrypted_session_key = cipher_rsa.encrypt(session_key)
        encrypted_key_len = len(encrypted_session_key)

        if encrypted_key_len not in CYPHER_LENGTH_TO_CODE:
            return 12

        encrypted_key_len_code = CYPHER_LENGTH_TO_CODE[encrypted_key_len]

        # writes code for cypher name
        out_file.write(int(1).to_bytes(1, byteorder=BYTEORDER, signed=False))
        # writes code for cypher key length
        out_file.write(int(encrypted_key_len_code).to_bytes(1, byteorder=BYTEORDER, signed=False))
        # writes code for cypher operation mode
        out_file.write(int(1).to_bytes(1, byteorder=BYTEORDER, signed=False))

        out_file.write(encrypted_session_key)

        # generate random initialization vector and writes it to file
        iv = get_random_bytes(BLOCK_SIZE)
        out_file.write(iv)

        cipher = AES.new(session_key, AES.MODE_CBC, iv=iv)

        with open(in_file_name, "rb") as in_file:
            file_empty = False
            # encrypts data
            while not file_empty:
                input_buffer = in_file.read(BUFFER_SIZE)
                # checks if last block has been read during encryption
                if len(input_buffer) != BUFFER_SIZE:
                    input_buffer = Padding.pad(input_buffer, BLOCK_SIZE, style='pkcs7')
                    file_empty = True

                # sends buffered data to output crypto function
                out_buffer = bytearray(len(input_buffer))
                cipher.encrypt(input_buffer, output=out_buffer)

                out_file.write(out_buffer)
        return 0


def decrypt_file(private_key: RSA.RsaKey, in_file_name: str, out_file_name: str):
    # opens destination file
    with open(in_file_name, mode="rb") as in_file:
        # reads code for cypher name
        cypher_code = int.from_bytes(in_file.read(1), byteorder=BYTEORDER, signed=False)
        # reads code for cypher key length
        cypher_length_code = int.from_bytes(in_file.read(1), byteorder=BYTEORDER, signed=False)
        # reads code for cypher operation mode
        cypher_mode_code = int.from_bytes(in_file.read(1), byteorder=BYTEORDER, signed=False)

        # checks if codes are valid
        if cypher_code not in CYPHERS \
                or cypher_length_code not in CYPHER_CODE_TO_LENGTH \
                or cypher_mode_code not in CYPHER_MODES:
            return 9

        cypher_key_length = CYPHER_CODE_TO_LENGTH[cypher_length_code]

        # reads encrypted symmetric key
        encrypted_session_key = in_file.read(cypher_key_length)
        if len(encrypted_session_key) != cypher_key_length:
            return 10

        # decrypts symmetric key
        cipher_rsa = PKCS1_OAEP.new(private_key)
        session_key = cipher_rsa.decrypt(encrypted_session_key)

        # reads initialisation vector
        iv = in_file.read(BLOCK_SIZE)
        if len(iv) != BLOCK_SIZE:
            return 11

        cipher = CYPHERS[cypher_code].new(session_key, CYPHER_MODES[cypher_mode_code], iv=iv)

        # opens file to write to
        with open(out_file_name, "wb") as out_file:
            file_empty = False
            # decrypts data
            while not file_empty:
                input_buffer = in_file.read(BUFFER_SIZE)

                # sends buffered data to output crypto function
                out_buffer = bytearray(len(input_buffer))
                cipher.decrypt(input_buffer, output=out_buffer)

                # checks if last block has been read during decryption
                if len(out_buffer) != BUFFER_SIZE:
                    out_buffer = Padding.unpad(out_buffer, BLOCK_SIZE, style='pkcs7')
                    file_empty = True
                out_file.write(out_buffer)
        return 0


def crypt_file(encrypt: bool, key_file_name: str, in_file_name: str, out_file_name: str):
    # check if file exists
    if not os.path.isfile(key_file_name):
        return 2

    if not os.path.isfile(in_file_name):
        return 3

    try:
        file = open(key_file_name, 'rb')
    except (OSError, IOError):
        return 4

    try:
        file = open(in_file_name, 'rb')
    except (OSError, IOError):
        return 5

    try:
        file = open(out_file_name, 'wb')
    except (OSError, IOError):
        return 6

    # print(RSA.import_key(open(key_file_name).read()))

    try:
        loaded_key = RSA.import_key(open(key_file_name).read())
    except (ValueError, IndexError, TypeError):
        return 7

    if encrypt:
        return encrypt_file(loaded_key, in_file_name, out_file_name)
    elif loaded_key.has_private():
        return decrypt_file(loaded_key, in_file_name, out_file_name)

    return 8


if __name__ == "__main__":
    # creates argument parser
    parser = ArgumentParser(description="Encrypts/Decrypts file using the AES cipher and then encrypt/decrypts AES key using RSA cipher.")

    # Adds program arguments
    parser.add_argument("-e", "--encrypt",
                        default=False,
                        action='store_true',
                        help="choose to encrypt")
    parser.add_argument("-d", "--decrypt",
                        default=False,
                        action='store_true',
                        help="choose to decrypt")
    parser.add_argument("key_file",
                        help="Path to file with public/private key")
    parser.add_argument("in_file",
                        help="file to be encrypted/decrypted")
    parser.add_argument("out_file",
                        help="file to store decrypted/encrypted file")

    # loads arguments
    args = parser.parse_args()

    # checks if only one flag is enabled
    if args.encrypt == args.decrypt:
        print(parser.print_help())
        sys.exit(1)

    returned = crypt_file(args.encrypt, args.key_file, args.in_file, args.out_file)
    sys.exit(returned)
