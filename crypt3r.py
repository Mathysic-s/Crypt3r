import argparse
import pathlib

from cryptography.fernet import Fernet, InvalidToken


def encdec_msg(filename, saveas):
    if args.verbosity == 0:
        pass  # Silent
    elif args.verbosity == 1:
        print(f"{parser.prog}: {filename.name} is encrypted") if not args.decrypt else print(
            f"{parser.prog}: {filename.name} is decrypted!")  # Crypt3r: foo.bar is encrypted!
    elif args.verbosity == 2:
        print(f"{parser.prog}: {filename.name} is encrypted as {saveas.name}!") if not args.decrypt else print(
            f"{parser.prog}: {filename.name} is decrypted as11 {saveas.name}!")  # Crypt3r: foo.bar is encrypted as
        # foo.bar.crypt!
    elif args.verbosity == 3:
        print(f"{parser.prog}: {filename.name} is encrypted as {saveas.absolute()}!") if not args.decrypt else print(
            f"{parser.prog}: {filename.name} is decrypted as {saveas.absolute()}!")  # Crypt3r: foo.bar is encrypted as
        # path\to\foo.bar.crypt!
    elif args.verbosity == 4:
        print(f"{parser.prog}: {filename.absolute()} is encrypted as {saveas.name}!") if not args.decrypt else print(
            f"{parser.prog}: {filename.absolute()} is decrypted as {saveas.name}!")  # Crypt3r: path\to\foo.bar is
        # encrypted as foo.bar.crypt!
    elif args.verbosity >= 5:
        print(f"{parser.prog}: {filename.absolute()} is encrypted as55 {saveas.absolute()}!") if not args.decrypt else \
            print(
                f"{parser.prog}: {filename.absolute()} is decrypted as55 {saveas.absolute()}!")  # Crypt3r:
        # path\to\foo.bar is
        # encrypted as path\to\foo.bar.crypt!


def deorencrypt_file(filename, key):
    try:
        with open(filename, 'rb') as file:
            file_data = file.read()

        f = Fernet(key)
        if not args.decrypt:  # Set encrypt/decrypt mode
            deorencrypted_data = f.encrypt(file_data)
        else:
            deorencrypted_data = f.decrypt(file_data)

        if args.no_replace and args.decrypt:  # if -nr -d
            saveas = filename.with_suffix("")
        elif args.decrypt:  # if -d
            if ".crypt" in filename.name:
                saveas = filename.rename(filename.with_suffix(""))
            else:
                saveas = filename
        elif args.no_replace:
            saveas = filename.with_name(filename.name + ".crypt")
        else:
            saveas = filename

        with open(saveas, 'wb') as file:
            file.write(deorencrypted_data)

        encdec_msg(filename, saveas)

    except PermissionError:
        print("Error writing: {}".format(filename))
    except InvalidToken:
        print(f"{parser.prog}: error: {filename}: File isn't crypt or the key is invalid for this file.")
    except ValueError:
        print(f"{parser.prog}: key: value error: The key must be 32 url-safe base64-encoded bytes.")


def deorencrypt_folder(foldername, key):
    for filename in walk(foldername):
        deorencrypt_file(pathlib.Path.joinpath(filename), key)


def walk(path):
    for p in pathlib.Path(path).iterdir():
        if p.is_dir():
            yield from walk(p)
            continue
        yield p.resolve()


def check_path(path):
    try:
        if path.is_file():
            return True
        elif path.is_dir():
            return False
        elif args.save_key and not path.touch():
            print("oi")
            if path.is_file():
                print("é arquivo")
                return True
            else:
                print("Não é arquivo")
                return False
            # return True if path.is_file() else False
        else:
            parser.error(f"'{path.absolute()}': Not a file or directory.")
    except FileNotFoundError:
        parser.error(f"'{path.absolute()}': Not this directory exist.")


def save_key(key, pathkey):
    with open(pathkey, 'wb') if check_path(pathkey) else open(pathkey.joinpath("key.txt"), 'wb') as file:
        file.write(key)
        file.close()
        print(f"Key was saved at: {pathlib.Path(file.name).absolute()}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(prog="Crypt3r")
    parser.add_argument("source", type=pathlib.Path, action="store", help="Directory or file to encrypt/decrypt")
    parser.add_argument("-o", "--output", type=pathlib.Path, action="store", default=pathlib.Path("./"), help="Output "
                                                                                                              "files")
    parser.add_argument("-sk", "--save-key", type=pathlib.Path, action="store", default=False, help="Save encryption "
                                                                                                    "key. (Default: "
                                                                                                    "./key.txt)")
    parser.add_argument("-k", "--key", action="store", help="Key for decryption (Require -d/--decrypt option.)")
    parser.add_argument("-d", "--decrypt", action="store_true", help="Decrypt (Require -k/--key option.)")
    parser.add_argument("-nr", "--no-replace", action="store_true", help="Don't replace original files "
                                                                         "creating/removing .crypt extension.")
    parser.add_argument("-v", "--verbosity", type=int, action="store", default=2, help="Verbosity mode values 0-5 ("
                                                                                       "Ex: -v 1, -v 3) (Default: -v "
                                                                                       "2)")
    parser.add_argument('--version', action='version', version='%(prog)s 1.0b coded by Mr Motta (mrmotta.com.br)')
    args = parser.parse_args()
    if args.verbosity < 0 or args.verbosity > 5:
        parser.error(f"argument -v/--verbosity: invalid int value: '{args.verbosity}'")
    if not args.decrypt:
        if args.key:
            parser.error(f"don't use the following arguments for encrypt: -k or --key")
        keyn = Fernet.generate_key()
    else:
        keyn = args.key
        if keyn is None:
            parser.error(f"the following arguments are required for decrypt: -k or --key")
        elif args.save_key:
            parser.error(f"don't use the following arguments for decrypt: -sk or --save-key")
    print(f"Save this key for decrypt: {keyn.decode('utf-8')}") if not args.decrypt else False
    deorencrypt_file(args.source, keyn) if check_path(args.source) else deorencrypt_folder(args.source, keyn)
    print(f"Save this key for decrypt: {keyn.decode('utf-8')}") if not args.decrypt else False
    save_key(keyn, args.save_key) if args.save_key else False
