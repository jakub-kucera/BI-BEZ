import sys
from argparse import ArgumentParser
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util import Padding

BUFFER_SIZE = 1024
KEY_SIZE = 16

# crypto_function = {True: cipher.encrypt, False: cipher.encrypt}
# (encrypt/decrypt, ECB/CBC)
FILE_EXTENSIONS_MODE = {"ECB": "_ecb", "CBC": "_cbc"}
FILE_DECRYPTED_EXTENSION = "_dec"
FILE_TYPE_EXTENSION = ".tga"

# creates argument parser
parser = ArgumentParser(description="Encrypts/Decrypts image files using the AES cipher with ECB/CBC mode.")

# Adds program arguments
parser.add_argument("-e", "--encrypt",
                    default=False,
                    action='store_true',
                    # choices=["-e", "-d"],
                    help="choose to encrypt/decrypt")
parser.add_argument("-d", "--decrypt",
                    default=False,
                    action='store_true',
                    help="choose to encrypt/decrypt")
parser.add_argument("operation_mode",
                    default="ECB",
                    choices=["ECB", "CBC"],
                    help="display $ at end of each line")
parser.add_argument("file",
                    help="file to encrypt/decrypt")

if __name__ == "__main__":

    # creates namespace with arguments
    args = parser.parse_args()

    if args.encrypt == args.decrypt:
        print("invalid -e -d args")
        print(parser.print_help())
        sys.exit(1)
        # todo make better

    print(args)

    # opening file with "with" takes care of exception handling, closing file
    with open(args.file, mode="rb") as f_in:

        file_name = args.file[:-4]
        if args.encrypt:
            file_name += FILE_EXTENSIONS_MODE[args.operation_mode] + FILE_TYPE_EXTENSION
        else:
            file_name += FILE_DECRYPTED_EXTENSION + FILE_TYPE_EXTENSION
        print(args.file)
        print(file_name)

        # reads beginning of header with constant size
        header = f_in.read(18)
        if header == -1:
            sys.exit(1)
        id_length = int(header[0])
        colormap_entry_count = int.from_bytes(header[5:7], byteorder='little')
        colormap_entry_size = int(header[7])

        print(header)
        # print(id_length)
        # print(colormap_entry_count)
        # print(colormap_entry_size)

        if (colormap_entry_count * colormap_entry_size) % 8 != 0:
            sys.exit(1)

        # reads rest of header with variable size
        header_extra = f_in.read(int(id_length + colormap_entry_count * colormap_entry_size / 8))
        if header_extra == -1:
            sys.exit(1)
        header += header_extra
        print(header)

        key = get_random_bytes(KEY_SIZE)
        cipher = AES.new(key, AES.MODE_ECB)

        # ciphertext, tag = cipher.encrypt_and_digest(data)

        with open(file_name, "wb") as f_out:
            f_out.write(header)
            file_not_empty = True
            while file_not_empty:
                input_buffer = f_in.read(BUFFER_SIZE)
                if len(input_buffer) != BUFFER_SIZE:
                    input_buffer = Padding.pad(input_buffer, KEY_SIZE, style='pkcs7')
                    file_not_empty = False
                # out_buffer = bytearray(1024)
                out_buffer = bytearray(len(input_buffer))
                cipher.encrypt(input_buffer, output=out_buffer)

                f_out.write(out_buffer)
