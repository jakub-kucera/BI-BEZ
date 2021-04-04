# Author Jakub Kucera <kucerj56@fit.cvut.cz>
# Date  29.3.2021
import os
import pathlib
import main
import filecmp

if __name__ == "__main__":
    image_file = pathlib.Path('examples/')
    original_files = []

    print("list all images")
    for entry in image_file.iterdir():
        if entry.is_file():
            print(entry)
            original_files += [entry]

    for file in original_files:
        print(50 * "=")

        file_name_full = str(file)
        print(f"File: {file_name_full}")
        file_name = file_name_full[:-4]
        file_name_ecb_encrypt = file_name + "_ecb.tga"
        file_name_ecb_decrypt = file_name + "_ecb_dec.tga"
        file_name_cbc_encrypt = file_name + "_cbc.tga"
        file_name_cbc_decrypt = file_name + "_cbc_dec.tga"

        status_ecd_encrypt = main.crypt_image(file_name_full, True, True)
        status_ecd_decrypt = main.crypt_image(file_name_ecb_encrypt, True, False)
        status_cbc_encrypt = main.crypt_image(file_name_full, False, True)
        status_cbc_decrypt = main.crypt_image(file_name_cbc_encrypt, False, False)

        if status_ecd_encrypt != 0 or status_ecd_decrypt != 0:
            print(f"\tERROR: ecd_encrypt: {status_ecd_encrypt}, ecd_decrypt: {status_ecd_decrypt}")
        else:
            comp_ecd = filecmp.cmp(file_name_full, file_name_ecb_decrypt, shallow=False)
            if comp_ecd:
                print("\tECD OK")
            else:
                print(f"\tERROR: ECD CMP encrypt/decrypt  test: {comp_ecd}")

        if status_cbc_encrypt != 0 or status_cbc_decrypt != 0:
            print(f"\tERROR: cbc_encrypt: {status_cbc_encrypt}, cbc_decrypt: {status_cbc_decrypt}")
        else:
            comp_cbc = filecmp.cmp(file_name_full, file_name_cbc_decrypt, shallow=False)
            if comp_cbc:
                print("\tCBC OK")
            else:
                print(f"\tERROR: CBC CMP encrypt/decrypt  test: {comp_cbc}")

    print(50*"=")

    for entry in image_file.iterdir():
        if entry.is_file():
            if entry in original_files:
                pass
                # print(f"Keeping file: {entry}")
            else:
                print(f"Deleting file: {entry}")
                os.remove(entry)
