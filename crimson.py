#!/usr/bin/env python3
import os
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import base64
from fuzzywuzzy import process 
import getpass
import pyperclip


BACKEND = default_backend()
SALT_SIZE = 16  # 128-bit salt
KEY_SIZE = 32  # 256-bit key
NONCE_SIZE = 12  # 96-bit nonce
TAG_SIZE = 16
ITERATIONS = 100000
FILE_PATH = "Passwords.txt"

def find_closest_string(target, string_list):
    closest_match = process.extractOne(target, string_list)
    return closest_match[0]


class Encryptor:
    @staticmethod
    def generate_key(password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=KEY_SIZE,
            salt=salt,
            iterations=ITERATIONS,
            backend=BACKEND
        )
        return kdf.derive(password.encode())

    @staticmethod
    def encrypt_file(file_path, password):
        """Encrypt the file and save it with .enc extension."""
        salt = os.urandom(SALT_SIZE)
        key = Encryptor.generate_key(password, salt)
        nonce = os.urandom(NONCE_SIZE)
        
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce),
            backend=BACKEND
        )
        
        encryptor = cipher.encryptor()
        
        try:
            with open(file_path, 'rb') as f:
                plaintext = f.read()
        except:
            with open(file_path, 'wb') as f:
                print('=== Initialisation complete - Created "Passwords.txt" file ===\n Please run again to start retreiving passwords')
                pass
        
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        
        with open(file_path + '.enc', 'wb') as f:
            f.write(salt + nonce + encryptor.tag + ciphertext)

        os.remove(file_path)
        
        print(f"File {file_path} encrypted successfully and plaintext deleted.")

    @staticmethod
    def decrypt_file(file_path, password):
        """Decrypt the file and save the result without .enc extension."""
        with open(file_path, 'rb') as f:
            salt = f.read(SALT_SIZE)
            nonce = f.read(NONCE_SIZE)
            tag = f.read(TAG_SIZE)
            ciphertext = f.read()
        
        key = Encryptor.generate_key(password, salt)
        
        cipher = Cipher(
            algorithms.AES(key),
            modes.GCM(nonce, tag),
            backend=BACKEND
        )
        
        decryptor = cipher.decryptor()
        
        try:
            plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        except Exception as e:
            print(f"Decryption failed: {e}")
            raise Exception
        
        with open(file_path.replace('.enc', ''), 'wb') as f:
            f.write(plaintext)
        
        print(f"File {file_path} decrypted successfully.")
        return True

def auth_decrypt():
    """Decrypts the file after the correct password is entered otherwise terminates the program"""
    count = 0
    valid = False
    while count < 3 and valid == False:
        password = getpass.getpass(prompt='Enter password: ')
        try:
            valid = Encryptor.decrypt_file(FILE_PATH+'.enc', password)
        except FileNotFoundError as e:
            Encryptor.encrypt_file(FILE_PATH, password)
            input("Press enter to quit:")
            quit()   
        except Exception as e:
            print(f"Incorrect password: {e}")
            count += 1
    if count == 3:
        quit()
    return password

def file_reader(file_path):
    with open(file_path, "r") as file:
    #Read all the lines from the file
        lines = [line.strip() for line in file]
    return lines

def text_parser(lines):
    string_list = lines
    before_comma = [s.split(',')[0].strip() for s in string_list]
    after_comma = [s.split(',', 1)[1].strip() for s in string_list]
    return before_comma, after_comma


if __name__ == "__main__":
    auth_decrypt()
    lines = file_reader(FILE_PATH)
    before_comma, after_comma = text_parser(lines)
    while True:
        print(f"List of accounts: \n {before_comma} \n {'='*30}")
        target_string = input("Please enter what you want:")
        closest = find_closest_string(target_string, before_comma)

        index = before_comma.index(closest)
        print(f"Your password is {after_comma[index]} it is saved to your clipboard")
        print(f"Password for {before_comma[index]}")
        pyperclip.copy(after_comma[index])
        try:
            os.remove(FILE_PATH)
            print("Plaintext deleted") 
        except:
            pass

        choice = int(input("Menu\n1). Get another password\n2). Quit\n:"))
        if choice == 1:
            pass
        elif choice == 2:
            quit()
