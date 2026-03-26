from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import struct
from pathlib import Path
from colorama import init, Fore, Style

# init colorama (CMD compatibility)
init(autoreset=True)

# ==================================================
# // Future Client Auth Decrypter
# // made by uefibootkit
# ==================================================

AUTH_KEY_HEX = "428A487E3361EF9C5FC20233485EA236"


# =========================
# Fake Gradient Printer
# =========================
def print_red_gradient(text: str):
    colors = [
        Fore.RED,
        Fore.RED,
        Fore.LIGHTRED_EX,
        Fore.LIGHTRED_EX
    ]

    for i, ch in enumerate(text):
        color = colors[int((i / max(len(text)-1, 1)) * (len(colors)-1))]
        print(color + ch, end="")
    print(Style.RESET_ALL)


# =========================
# Crypto Core
# =========================
class KeyConverter:
    @staticmethod
    def to_byte_array(hex_string: str) -> bytes:
        return bytes.fromhex(hex_string)


class FileCrypto:
    @staticmethod
    def decrypt_file(data: bytes, key: bytes, iv: bytes) -> bytes:
        cipher = AES.new(key, AES.MODE_CBC, iv)
        return unpad(cipher.decrypt(data), AES.block_size)


class AuthKeyDecryptor:
    @staticmethod
    def read_block(f) -> bytes:
        length_bytes = f.read(4)
        if len(length_bytes) != 4:
            raise ValueError("Invalid auth key file format")

        length = struct.unpack(">I", length_bytes)[0]
        return f.read(length)

    @staticmethod
    def decrypt(path: Path):
        key = KeyConverter.to_byte_array(AUTH_KEY_HEX)

        with open(path, "rb") as f:
            iv = AuthKeyDecryptor.read_block(f)
            enc_user = AuthKeyDecryptor.read_block(f)
            enc_pass = AuthKeyDecryptor.read_block(f)

            username = FileCrypto.decrypt_file(enc_user, key, iv).decode("utf-8")
            password = FileCrypto.decrypt_file(enc_pass, key, iv).decode("utf-8")

            return username, password


# =========================
# MAIN (INTERACTIVE CLI)
# =========================
def main():
    print()
    print_red_gradient("Future Client Auth Decrypter")
    print(Fore.LIGHTRED_EX + "// made by " + Fore.RED + Style.BRIGHT + "uefibootkit")
    print(Fore.LIGHTRED_EX + "// -----------------------------------------------\n")

    print(Fore.RED + "[INFO]" + Style.RESET_ALL + " Drag & drop the auth_key file here")
    print(Fore.RED + "[INFO]" + Style.RESET_ALL + " or paste the file path and press ENTER\n")

    path_input = input(Fore.RED + "auth_key > " + Style.RESET_ALL).strip().strip('"')

    if not path_input:
        print(Fore.RED + "[ERROR] No file provided.")
        return

    path = Path(path_input)

    if not path.exists():
        print(Fore.RED + "[ERROR] File not found.")
        return

    try:
        username, password = AuthKeyDecryptor.decrypt(path)

        output_path = path.with_suffix(".txt")

        with open(output_path, "w", encoding="utf-8") as f:
            f.write("// Future Client Auth Decrypter\n")
            f.write("// made by uefibootkit\n\n")
            f.write(f"Username: {username}\n")
            f.write(f"Password: {password}\n")

        print("\n" + Fore.RED + "[SUCCESS]" + Style.RESET_ALL + " Auth key decrypted\n")
        print(Fore.LIGHTRED_EX + "Username:" + Style.RESET_ALL, username)
        print(Fore.LIGHTRED_EX + "Password:" + Style.RESET_ALL, password)
        print("\n" + Fore.RED + "[OUTPUT]" + Style.RESET_ALL + f" Saved to: {output_path}")

    except Exception as e:
        print(Fore.RED + "[ERROR] Decryption failed")
        print(str(e))


if __name__ == "__main__":
    main()