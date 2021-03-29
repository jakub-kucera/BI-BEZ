# Author Jakub Kucera <kucerj56@fit.cvut.cz>
# Date  28.3.2021
import os
import sys
from argparse import ArgumentParser
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util import Padding

BUFFER_SIZE = 1024
BLOCK_SIZE = 16
IV_SIZE = 16
KEY_DEFAULT = b"0123456789ABCDEF"
IV_DEFAULT = b'FEDCBA9876543210'
FILE_EXTENSION_MODES = {True: "_ecb", False: "_cbc"}
FILE_DECRYPTED_EXTENSION = "_dec"
FILE_TYPE_EXTENSION = ".tga"


def crypt_image(file: str, use_ecb: bool = True, encrypt: bool = True, key: bytearray = KEY_DEFAULT,
                iv: bytearray = IV_DEFAULT):
    # check if file exists
    if not os.path.isfile(file):
        return 2

    # opens file
    with open(file, mode="rb") as file_in:
        # reads beginning of header with constant size
        header = file_in.read(18)
        if len(header) != 18:
            return 3
        id_length = int(header[0])
        colormap_entry_count = int.from_bytes(header[5:7], byteorder='little')
        colormap_entry_size = int(header[7])

        # exits program when header data is corrupted
        if (colormap_entry_count * colormap_entry_size) % 8 != 0:
            return 4

        # reads rest of header with variable size
        extra_header_size = int(id_length + colormap_entry_count * colormap_entry_size / 8)
        header_extra = file_in.read(extra_header_size)
        if len(header_extra) != extra_header_size:
            return 5
        header += header_extra

        # gets output file name
        file_name = file[:-4]

        file_name += FILE_EXTENSION_MODES[use_ecb] if encrypt else FILE_DECRYPTED_EXTENSION
        file_name += FILE_TYPE_EXTENSION

        # creates AES object with its operation mode, key and optional IV
        cipher = AES.new(key, AES.MODE_ECB) if use_ecb else AES.new(key, AES.MODE_CBC, iv=iv)
        crypt_function = cipher.encrypt if encrypt else cipher.decrypt

        # writes to output file
        with open(file_name, "wb") as file_out:
            # copies header data
            file_out.write(header)
            file_empty = False
            # decrypts/encrypts data
            while not file_empty:
                input_buffer = file_in.read(BUFFER_SIZE)
                # checks if last block has been read during encryption
                if len(input_buffer) != BUFFER_SIZE and encrypt:
                    input_buffer = Padding.pad(input_buffer, BLOCK_SIZE, style='pkcs7')
                    file_empty = True

                # sends buffered data to output crypto function
                out_buffer = bytearray(len(input_buffer))
                crypt_function(input_buffer, output=out_buffer)

                # checks if last block has been read during decryption
                if len(out_buffer) != BUFFER_SIZE and not encrypt:
                    out_buffer = Padding.unpad(out_buffer, BLOCK_SIZE, style='pkcs7')
                    file_empty = True
                file_out.write(out_buffer)
    return 0


if __name__ == "__main__":
    # creates argument parser
    parser = ArgumentParser(description="Encrypts/Decrypts image files using the AES cipher with ECB/CBC mode.")

    # Adds program arguments
    parser.add_argument("-e", "--encrypt",
                        default=False,
                        action='store_true',
                        help="choose to encrypt")
    parser.add_argument("-d", "--decrypt",
                        default=False,
                        action='store_true',
                        help="choose to decrypt")
    parser.add_argument("operation_mode",
                        choices=["ECB", "CBC"],
                        help="display $ at end of each line")
    parser.add_argument("file",
                        help="file to encrypt/decrypt")

    # loads arguments
    args = parser.parse_args()

    # checks if only one flag is enabled
    if args.encrypt == args.decrypt:
        print(parser.print_help())
        sys.exit(1)

    # key = get_random_bytes(BLOCK_SIZE)
    returned = crypt_image(args.file, args.operation_mode == "ECB", args.encrypt)
    sys.exit(returned)
