import argparse
import pathlib
import sys
import os
import platform
from cryptography.fernet import Fernet, InvalidToken
from colorama import init, Fore, Back


class crypt3r_styles():
    def __init__(self) -> None:
        self.prog = f"\n{Fore.BLACK+Back.CYAN+parser.prog+Back.WHITE}:{Back.RESET+Fore.RESET}"
        self.info = f"{Back.GREEN+Fore.WHITE}INFO{Back.WHITE+Fore.BLACK}:{Back.RESET+Fore.RESET}"
        self.erro = f"{Back.RED}ERROR{Back.WHITE+Fore.BLACK}:{Back.RESET+Fore.RESET}"
        self.codeby = f"{Fore.MAGENTA}Coded By {Fore.BLACK+Back.MAGENTA}Mr. Motta{Back.RESET+Fore.RESET}"
        self.site = f"{Fore.BLUE}https://mrmotta.com.br{Fore.RESET}"
    def banner(self):
        print(f'''
\t\t             {Fore.GREEN},gaaaaaaaagaaaaaaaaaaaaagaaaaaaaag,
\t\t           ,aP8b    _,dYba,       ,adPb,_    d8Ya,
\t\t         ,aP"  Yb_,dP"   "Yba, ,adP"   "Yb,_dP  "Ya,
\t\t       ,aP"    _88"         )888(         "88_    "Ya,
\t\t     ,aP"   _,dP"Yb      ,adP"8"Yba,      dP"Yb,_   "Ya,
\t\t   ,aPYb _,dP8    Yb  ,adP"   8   "Yba,  dP    8Yb,_ dPYa,
\t\t ,aP"  YdP" dP     YbdP"      8      "YbdP     Yb "YbP  "Ya,
\t\tI8aaaaaa8aaa8baaaaaa88aaaaaaaa8aaaaaaaa88aaaaaad8aaa8aaaaaa8I{Fore.RESET}
\t\t{Fore.YELLOW}::::::  {Fore.CYAN}.oPYo.{Fore.YELLOW} .:::::::::::::::::::. {Fore.CYAN}o  .oPYo.{Fore.YELLOW}  :::::::::::::
\t\t{Fore.YELLOW}::::::  {Fore.CYAN}8    8{Fore.YELLOW}  :::::::::::::::::::  {Fore.CYAN}8      `8{Fore.YELLOW}  :::::::::::::     
\t\t{Fore.YELLOW}::::::  {Fore.CYAN}8      oPYo. o    o .oPYo.  o8P   .oP' oPYo.{Fore.YELLOW}  :::::::
\t\t{Fore.YELLOW}::::::  {Fore.CYAN}8      8  `' 8    8 8    8   8     `b. 8  `'{Fore.YELLOW}  :::::::
\t\t{Fore.YELLOW}::::::  {Fore.CYAN}8    8 8     8    8 8    8   8      :8 8{Fore.YELLOW}  :::::::::::
\t\t{Fore.YELLOW}::::::  {Fore.CYAN}`YooP' 8     `YooP8 8YooP'   8  `YooP' 8{Fore.YELLOW}  :::::::::::     
\t\t{Fore.YELLOW}::::::..:.....:..:::::..  {Fore.CYAN}8 8{Fore.YELLOW} ....:::..::.....:..::::::::::::
\t\t{Fore.YELLOW}::::::::::::::::::::: {Fore.CYAN}ooP'.8{Fore.YELLOW} :::::::::::::::::::::::::::::::{Fore.GREEN}
\t\t`Yb,   d8a, Ya      d8b,      8      ,d8b      aP ,a8b   ,dP'
\t\t  "Yb,dP "Ya "8,   dI "Yb,    8    ,dP" Ib   ,8" aP" Yb,dP"
\t\t    "Y8,   "YaI8, ,8'   "Yb,  8  ,dP"   `8, ,8IaP"   ,8P"
\t\t      "Yb,   `"Y8ad'      "Yb,8,dP"      `ba8P"'   ,dP"
\t\t        "Yb,    `"8,        "Y8P"        ,8"'    ,dP"
\t\t          "Yb,    `8,         8         ,8'    ,dP"
\t\t            "Yb,   `Ya        8        aP'   ,dP"
\t\t              "Yb,   "8,      8      ,8"   ,dP"
\t\t                "Yb,  `8,     8     ,8'  ,dP"   {self.codeby}
\t\t                  {Fore.GREEN}"Yb, `Ya    8    aP' ,dP"   {self.site}
\t\t                    {Fore.GREEN}"Yb, "8,  8  ,8" ,dP"
\t\t                      "Yb,`8, 8 ,8',dP"
\t\t                        "Yb,Ya8aP,dP"
\t\t                          "Y88888P"
\t\t                            "Y8P"
\t\t                              "
                ''')

def encdec_msg(filename, saveas):
    if args.verbosity == 0:
        pass  # Silent
    elif args.verbosity == 1:
        print(f"{s.prog} {s.info}  {Fore.YELLOW}{filename.name}{Fore.BLUE} is {Back.RED+'ENCRYPTED' if not args.decrypt else Back.GREEN+'DECRYPTED'}{Back.RESET+Fore.BLUE} !")
        # Crypt3r: foo.bar is encrypted!
    elif args.verbosity == 2:
        print(f"{s.prog} {s.info}  {Fore.YELLOW}{filename.name}{Fore.BLUE} is {Back.RED+'ENCRYPTED' if not args.decrypt else Back.GREEN+'DECRYPTED'}{Back.RESET} as {Fore.YELLOW}{saveas.name}{Fore.BLUE} !")   # Crypt3r: foo.bar is encrypted as
        # foo.bar.crypt!
    elif args.verbosity == 3:
        print(f"{s.prog} {s.info}  {Fore.YELLOW}{filename.name}{Fore.BLUE} is {Back.RED+'ENCRYPTED' if not args.decrypt else Back.GREEN+'DECRYPTED'}{Back.RESET} as {Fore.YELLOW}{saveas.absolute()}{Fore.BLUE} !")
        # Crypt3r: foo.bar is encrypted as path\to\foo.bar.crypt!
    elif args.verbosity == 4:
        print(f"{s.prog} {s.info}  {Fore.YELLOW}{filename.absolute()}{Fore.BLUE} is {Back.RED+'ENCRYPTED' if not args.decrypt else Back.GREEN+'DECRYPTED'}{Back.RESET} as {Fore.YELLOW}{saveas.name}{Fore.BLUE} !")
        # Crypt3r: path\to\foo.bar is encrypted as foo.bar.crypt!
    elif args.verbosity >= 5:
        print(f"{s.prog} {s.info}  {Fore.YELLOW}{filename.absolute()}{Fore.BLUE} is {Back.RED+'ENCRYPTED' if not args.decrypt else Back.GREEN+'DECRYPTED'}{Back.RESET} as {Fore.YELLOW}{saveas.absolute()}{Fore.BLUE} !")
        # Crypt3r: path\to\foo.bar is encrypted as path\to\foo.bar.crypt!


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
            file.close()
        encdec_msg(filename, saveas)
        return 1

    except PermissionError:
        print(f"{s.prog} {s.erro} {Fore.YELLOW}No permission to write {Fore.RED}{filename}")
        return 0
    except InvalidToken:
        print(f"{s.prog} {s.erro} {Fore.YELLOW}{filename}{Fore.RESET+Fore.RED} isn't crypt or the key is invalid for this file.\n")
        return 0
    except ValueError:
        print(f"{s.prog} {s.erro} The{Fore.YELLOW}key{Fore.RESET+Fore.RED} must be 32 url-safe base64-encoded bytes.\n")
        return 0
    except Exception as err:
        print(f"{s.prog} {s.erro} {Fore.RED}{err}\n")
        return 0


def deorencrypt_folder(foldername, key):
    total_files = 0
    deorencrypt_success = 0
    for filename in walk(foldername):
        deorencrypt_success += deorencrypt_file(pathlib.Path.joinpath(filename), key)
        total_files+=1
    return {"success":deorencrypt_success,"total":total_files}


def walk(path):
    try:
        for p in pathlib.Path(path).iterdir():
            if p.is_dir():
                yield from walk(p)
                continue
            yield p.resolve()
    except PermissionError:
        print(f"{s.prog} {s.erro} {Fore.RED}No permission to write {Fore.YELLOW}{p}")


def check_path(path):
    try:
        if path.is_file():
            return True
        elif path.is_dir():
            return False
        elif args.save_key and not path.touch():
            if path.is_file():
                #é arquivo
                print(f" Save this key for decrypt: {keyn.decode('utf-8')}") if not args.decrypt else False
                return True
            else:
                #Não é arquivo
                print(f"Save this key for decrypt: {keyn.decode('utf-8')}") if not args.decrypt else False
                return False
        else:
            sys.exit(f"\n{s.prog} {s.erro} {Fore.YELLOW}'{path.absolute()}'{Fore.RED} Not a file or directory.\n")
    except FileNotFoundError:
        sys.exit(f"\n{s.prog} {s.erro} {Fore.YELLOW}'{path.absolute()}'{Fore.RED} Not this directory exist.\n")


def save_key(key, pathkey):
    with open(pathkey, 'wb') if check_path(pathkey) else open(pathkey.joinpath("key.txt"), 'wb') as file:
        file.write(key)
        file.close()
        print(f"\t\t{Fore.YELLOW}key{Fore.BLUE} was saved for {Back.GREEN}DECRYPT{Back.WHITE}:{Back.RESET} {Fore.YELLOW}{pathlib.Path(file.name).absolute()}\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(exit_on_error=False, prog="Crypt3r")
    init(autoreset=True)
    s = crypt3r_styles()
    s.banner()
    
    parser.add_argument("source", type=pathlib.Path, default=False, action="store", help="Directory or file to encrypt/decrypt")
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
    parser.add_argument('--version', action='version', version=f'{s.prog} {Fore.YELLOW}1.0b {s.codeby} {Fore.YELLOW}({s.site+Fore.YELLOW})')
    
    try:
        args = parser.parse_args()
    except BaseException as e: # GAMBIARRA
        if str(e.with_traceback(e.__traceback__)) == "2":
            os.system("cls") if platform.system() == "Windows" else os.system("clear")
            s.banner()
            parser.print_usage()
            sys.exit(f"{s.prog} {s.erro} {Fore.RED}the following arguments are required: source")
        elif str(e.with_traceback(e.__traceback__)) == "0":
            sys.exit(0)
        else:
            sys.exit(f"{s.prog} {s.erro} {Fore.RED}{e.with_traceback(e.__traceback__)}. (--version for contact)")
    
    if args.verbosity < 0 or args.verbosity > 5:
        sys.exit(f"\n{s.prog} {s.erro} {Fore.YELLOW}argument -v/--verbosity:{Fore.RED} invalid int value: {Fore.YELLOW}'{args.verbosity}'\n")
    if not args.decrypt:
        if args.key: # Don't use for decrypt -k/--key 
            sys.exit(f"\n{s.prog} {s.erro} {Fore.YELLOW}{Fore.RED} the following arguments for encrypt:{Fore.YELLOW} -k or --key\n")
        keyn = Fernet.generate_key()
    else:
        keyn = args.key
        if keyn is None: # -k/--key required for decrypt
            sys.exit(f"\n{s.prog} {s.erro} {Fore.RED}the following arguments are {Fore.YELLOW}required{Fore.RED} for decrypt: {Fore.YELLOW}-k or --key")
        elif args.save_key: # Don't use -sk/--save-key for decrypt
            sys.exit(f"\n{s.prog} {s.erro} {Fore.YELLOW}don't use{Fore.RED} the following arguments for decrypt: {Fore.YELLOW}-sk or --save-key\n")
    deorencrypt_result = deorencrypt_file(args.source, keyn) if check_path(args.source) else deorencrypt_folder(args.source, keyn)
    
    if type(deorencrypt_result) == dict:
        print(f"\n{s.prog} {s.info}")
        print(f"\t\t{Fore.BLUE}Total files {Back.YELLOW}ANALYZED{Back.WHITE}:{Back.RESET} {Fore.YELLOW}{deorencrypt_result['total']}")
        print(f"\t\t{Fore.BLUE}Total Files {Back.RED}ENCRYPTED{Back.WHITE}:{Back.RESET} {Fore.YELLOW}{deorencrypt_result['success']}")
        print(f"\t\t{Fore.BLUE}Total files not {Back.RED}ENCRYPTED{Back.WHITE}:{Back.RESET} {Fore.YELLOW}{deorencrypt_result['total']-deorencrypt_result['success']}")
    save_key(keyn, args.save_key) if args.save_key else print(f"\n{s.prog} {s.info}  {Fore.BLUE}Save this {Fore.YELLOW}key{Fore.BLUE} for {Back.GREEN}DECRYPT{Back.WHITE}:{Back.RESET}{Back.RESET+Fore.YELLOW} {keyn.decode('utf-8')}{Back.RESET}\n")
