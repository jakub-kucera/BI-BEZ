# Author Jakub Kucera <kucerj56@fit.cvut.cz>
# Date  14.4.2021
import os
import pathlib

from Crypto.PublicKey import RSA

import main
import filecmp

PRIVATE_KEY_FILE_VALID = "privkey_for_test.pem"
PUBLIC_KEY_FILE_VALID = "pubkey_for_test.pem"


def test_valid(directory: str = 'tests/valid/', key_length: int = 2048):
    print(50 * "=")
    print("Testing valid files:")
    file_dir = pathlib.Path(directory)
    original_files = []

    ok_counter = 0
    bad_counter = 0

    # print("list all original files")
    for entry in file_dir.iterdir():
        if entry.is_file():
            # print(entry)
            original_files += [entry]

    # generate public and private RSA keys
    key = RSA.generate(key_length)
    private_key_generated = key.export_key()
    with open(directory + PRIVATE_KEY_FILE_VALID, "wb") as file_out:
        file_out.write(private_key_generated)

    public_key_generated = key.publickey().export_key()
    with open(directory + PUBLIC_KEY_FILE_VALID, "wb") as file_out:
        file_out.write(public_key_generated)

    for file in original_files:
        # print(50 * "=")

        file_name_full = str(file)
        print(f"File: {file_name_full}")
        file_name, extension_name = file_name_full.split(sep='.')
        file_name_encrypted = file_name + "_enc.bin"
        file_name_decrypted = file_name + "_enc_dec." + extension_name

        status_encrypt = main.crypt_file(True, directory + PUBLIC_KEY_FILE_VALID, file_name_full, file_name_encrypted)
        status_decrypt = main.crypt_file(False, directory + PRIVATE_KEY_FILE_VALID, file_name_encrypted, file_name_decrypted)

        if status_encrypt != 0 or status_decrypt != 0:
            print(f"\tERROR: encrypt: {status_encrypt}, decrypt: {status_decrypt}")
            bad_counter += 1
        else:
            comp_ecd = filecmp.cmp(file_name_full, file_name_decrypted, shallow=False)
            if comp_ecd:
                print("\tOK: Files match")
                ok_counter += 1
            else:
                print(f"\tERROR: Files differ test")
                bad_counter += 1

    print(f"Valid test: {ok_counter}/{ok_counter+bad_counter} passed")

    print(50 * "=")

    for entry in file_dir.iterdir():
        if entry.is_file():
            if entry in original_files:
                pass
                # print(f"Keeping file: {entry}")
            else:
                # print(f"Deleting file: {entry}")
                os.remove(entry)


def test_invalid(directory: str = 'tests/invalid/'):
    print(50 * "=")
    print("Testing invalid files:")
    file_dir = pathlib.Path(directory)
    original_files = []

    ok_counter = 0
    bad_counter = 0

    for entry in file_dir.iterdir():
        if entry.is_file():
            # print(entry)
            original_files += [entry]

    for file in original_files:
        # print(50 * "=")

        file_name_full = str(file)
        print(f"File: {file_name_full}")
        file_name, extension_name = file_name_full.split(sep='.')
        file_name_decrypted = file_name + "_dec." + extension_name

        status_decrypt = main.crypt_file(False, f"{directory}privkey.pem", file_name_full, file_name_decrypted)

        if status_decrypt == 0:
            print(f"\tERROR: decrypted successfully, but was supposed to fail.")
            bad_counter += 1
        else:
            print(f"\tOK: decryption failed, error code: {status_decrypt}")
            ok_counter += 1

    print(f"Invalid test: {ok_counter}/{ok_counter+bad_counter} passed")

    print(50 * "=")

    for entry in file_dir.iterdir():
        if entry.is_file():
            if entry in original_files:
                pass
                # print(f"Keeping file: {entry}")
            else:
                # print(f"Deleting file: {entry}")
                os.remove(entry)


if __name__ == "__main__":
    test_valid(key_length=1024)
    test_valid(key_length=2048)
    test_valid(key_length=3072)
    test_valid(key_length=4096)
    test_invalid()
