import argparse
from modules.functions import *
from modules.functions_2 import *
from modules.style_and_banners import *
from os import getcwd
from re import match, compile
from datetime import datetime
from sys import exit as syexit




# Main Fuction
def main(calculate, id_hash, compare, decrypt, encrypt, file, directory, export, hash, algorithm, block_size, wordlist, h1, h2, num_p, string):
    
    current_date_time = datetime.now()
    formatted_date_time = current_date_time.strftime("%Y-%m-%d %H:%M:%S")




    if export != None and export == "./":
        export_path = getcwd()
    elif export != None and export != "./":
        export_path = export



    if calculate:
        if algorithm == None:
            algorithm = "sha256"
        else:
            algorithm = algorithm.lower()


        if block_size == None:
            block_size = 65536
        if file != None and directory != None:
            print(colorize_text("Error: You can only choose --file or --dir, not both", "red"))
            syexit()
        elif (file == None and directory == None) and hash != None:
            print(colorize_text("Error: You need to add --file or --dir, and --hash is not valid for --calculate", "red"))
            syexit()
        
        elif hash != None:
            print(colorize_text("Error: --hash is not valid for --calculate", "red"))
            syexit()

        elif (file == None and directory == None) and wordlist != None:
            print(colorize_text("Error: You need to add --file or --dir, and --wordlist is not valid for --calculate", "red"))
            syexit()
        elif wordlist != None:
            print(colorize_text("Error: --wordlist is not valid for --calculate", "red"))
            syexit()

        elif (file == None and directory == None) and h1 != None:
            print(colorize_text("Error: You need to add --file or --dir, and --h1 is not valid for --calculate", "red"))
            syexit()

        elif h1 != None:
            print(colorize_text("Error: --h1 is not valid for --calculate", "red"))
            syexit()

        elif (file == None and directory == None) and h2 != None:
            print(colorize_text("Error: You need to add --file or --dir, and --h2 is not valid for --calculate", "red"))
            syexit()

        elif h2 != None:
            print(colorize_text("Error: --h2 is not valid for --calculate", "red"))
            syexit()

        elif file == None and directory == None:
            print(colorize_text("Error: You need to add --file or --dir", "red"))
            syexit()
        




        
        elif file != None and directory == None:

            if export != None:
                    try:
                        algorithm = is_valid_hash_type(algorithm)
                        if algorithm == "error":
                            print(colorize_text("Error: Invalid hash type (--algorithm)", "red"))
                            syexit()
                        init_banner()
                        file_hash = calculate_file_hash(file, algorithm, block_size)
                        print(colorize_text("\n                        [!] INFORMATION", "cyan", "bold"))
                        print(colorize_text("\nDATE:", "cyan", "bold")+colorize_text(f" {formatted_date_time}", "yellow"))
                        print(colorize_text("\nFILE:", "cyan", "bold")+colorize_text(f" {file}", "yellow"))
                        print(colorize_text("\nALGORITHM:", "cyan", "bold")+colorize_text(f" {algorithm.upper()}", "yellow"))
                        print(colorize_text("\nHASH:", "cyan", "bold")+colorize_text(f" {file_hash}", "yellow"))
                        separator("cyan")
                        with open(f"{export_path}", "w") as export_file:
                                
                            export_file.write("##############################")
                            export_file.write("\n##          REPORT          ##")
                            export_file.write("\n##############################\n\n")
                            export_file.write(f"DATE: {formatted_date_time}\n")
                            export_file.write(f"ALGORITHM: {algorithm.upper()}\n\n")
                            export_file.write(f"FILE: {file}\n")
                            export_file.write(f"HASH: {file_hash}\n\n")
                    except:
                        print(colorize_text("Error: Error calculating hash", "red"))
                        syexit()
            else:
                    try:
                        algorithm = is_valid_hash_type(algorithm)
                        if algorithm == "error":
                            print(colorize_text("Error: Invalid hash type (--algorithm)", "red"))
                            syexit()
                        init_banner()
                        file_hash = calculate_file_hash(file, algorithm, block_size)
                        print(colorize_text("\n                        [!] INFORMATION", "cyan", "bold"))
                        print(colorize_text("\nDATE:", "cyan", "bold")+colorize_text(f" {formatted_date_time}", "yellow"))
                        print(colorize_text("\nFILE:", "cyan", "bold")+colorize_text(f" {file}", "yellow"))
                        print(colorize_text("\nALGORITHM:", "cyan", "bold")+colorize_text(f" {algorithm.upper()}", "yellow"))
                        print(colorize_text("\nHASH:", "cyan", "bold")+colorize_text(f" {file_hash}", "yellow"))
                        separator("cyan")
                    except:
                        print(colorize_text("Error: Error calculating hash", "red"))
                        syexit()

        elif file == None and directory != None:

            if export != None:
                try:
                    algorithm = is_valid_hash_type(algorithm)
                    if algorithm == "error":
                        print(colorize_text("Error: Invalid hash type (--algorithm)", "red"))
                        syexit()
                    hashes = calculate_hashes_directory(directory, algorithm, block_size)
                    init_banner()
                    print(colorize_text("\n                        [!] INFORMATION", "cyan", "bold"))
                    print(colorize_text("\nDATE:", "cyan", "bold")+colorize_text(f" {formatted_date_time}", "yellow"))
                    print(colorize_text("\nDIR:", "cyan", "bold")+colorize_text(f" {directory}", "yellow"))
                    separator("cyan")
                    with open(f"{export_path}", "w") as export_file:
                        export_file.write("##############################")
                        export_file.write("\n##          REPORT          ##")
                        export_file.write("\n##############################\n\n")
                        export_file.write(f"DATE: {formatted_date_time}\n")
                        export_file.write(f"ALGORITHM: {algorithm.upper()}\n\n")


                    for file, hash_value in hashes.items():
                        print(colorize_text("\nFILE:", "cyan", "bold")+colorize_text(f" {file}", "yellow"))
                        print(colorize_text("\nALGORITHM:", "cyan", "bold")+colorize_text(f" {algorithm.upper()}", "yellow"))
                        print(colorize_text("\nHASH:", "cyan", "bold")+colorize_text(f" {hash_value}", "yellow"))
                        separator("cyan")

                        with open(f"{export_path}", "a") as export_file:

                            export_file.write(f"FILE: {file}\n")
                            export_file.write(f"HASH: {hash_value}\n\n")

                except:
                        print(colorize_text("Error: Error calculating hash", "red"))
                        syexit()




            else:
                
                try:
                    hashes = calculate_hashes_directory(directory, algorithm, block_size)
                    init_banner()
                    print(colorize_text("\n                        [!] INFORMATION", "cyan", "bold"))
                    print(colorize_text("\nDATE:", "cyan", "bold")+colorize_text(f" {formatted_date_time}", "yellow"))
                    print(colorize_text("\nDIR:", "cyan", "bold")+colorize_text(f" {directory}", "yellow"))
                    separator("cyan")
                    for file, hash_value in hashes.items():
                        print(colorize_text("\nFILE:", "cyan", "bold")+colorize_text(f" {file}", "yellow"))
                        print(colorize_text("\nALGORITHM:", "cyan", "bold")+colorize_text(f" {algorithm.upper()}", "yellow"))
                        print(colorize_text("\nHASH:", "cyan", "bold")+colorize_text(f" {hash_value}", "yellow"))
                        separator("cyan")

                except:
                        print(colorize_text("Error: Error calculating hash", "red"))
                        syexit()

    elif id_hash:

        if hash != None:
            hash = hash.lower()

        if directory != None:
            print(colorize_text("Error: --dir is not valid for --id-hash", "red"))
            syexit()
        elif wordlist != None:
            print(colorize_text("Error: --wordlist is not valid for --id-hash", "red"))
            syexit()
        elif algorithm != None:
            print(colorize_text("Error: --algorithm is not valid for --id-hash", "red"))
            syexit()
        elif block_size != None:
            print(colorize_text("Error: --block_size is not valid for --id-hash", "red"))
            syexit()
        elif file != None and hash != None:
            print(colorize_text("Error: You need to provide a hash (--hash) or file (--file), not both", "red"))
            syexit()
        elif file == None and hash == None:
            print(colorize_text("Error: You need to provide a hash (--hash) or file (--file)", "red"))
            syexit()

        elif hash != None and file == None:


            if not is_hash(hash):
                print(colorize_text("Error: You need to provide a valid hash (--hash)", "red"))
                syexit()

            else:

                if export != None:
                    hash_id = detect_hash_type(hash)
                    init_banner()
                    print(colorize_text("\n                        [!] INFORMATION", "cyan"))
                    print(colorize_text("\nDATE:", "cyan", "bold")+colorize_text(f" {formatted_date_time}", "yellow"))
                    print(colorize_text("\nHASH:", "cyan", "bold")+colorize_text(f" {hash}", "yellow"))
                    print(colorize_text("\nALGORITHM:", "cyan", "bold")+colorize_text(f" {hash_id.upper()}", "yellow"))
                    with open(f"{export_path}", "w") as export_file:
                            
                        export_file.write("##############################")
                        export_file.write("\n##          REPORT          ##")
                        export_file.write("\n##############################\n\n")
                        export_file.write(f"DATE: {formatted_date_time}\n")
                        export_file.write(f"ALGORITHM: {hash_id.upper()}\n")
                        export_file.write(f"HASH: {hash}")
                else:

                    hash_id = detect_hash_type(hash)
                    init_banner()
                    print(colorize_text("\n                        [!] INFORMATION", "cyan"))
                    print(colorize_text("\nDATE:", "cyan", "bold")+colorize_text(f" {formatted_date_time}", "yellow"))
                    print(colorize_text("\nHASH:", "cyan", "bold")+colorize_text(f" {hash}", "yellow"))
                    print(colorize_text("\nALGORITHM:", "cyan", "bold")+colorize_text(f" {hash_id.upper()}", "yellow"))

        elif hash == None and file != None:        
            
            if export != None:
                try:

                    
                    hash_list = read_hashes_from_file(file)

                    init_banner()
                    print(colorize_text("\n                        [!] INFORMATION", "cyan"))
                    print(colorize_text("\nDATE:", "cyan", "bold")+colorize_text(f" {formatted_date_time}", "yellow"))
                    separator("cyan")
                    with open(f"{export_path}", "w") as export_file:
                        export_file.write("##############################")
                        export_file.write("\n##          REPORT          ##")
                        export_file.write("\n##############################\n\n")
                        export_file.write(f"DATE: {formatted_date_time}\n\n")
                    for hash in hash_list:

                        hash_id = detect_hash_type(hash)

                        
                        print(colorize_text("\nHASH:", "cyan", "bold")+colorize_text(f" {hash}", "yellow"))
                        print(colorize_text("\nTYPE:", "cyan", "bold")+colorize_text(f" {hash_id.upper()}", "yellow"))
                        with open(f"{export_path}", "a") as export_file:
                            export_file.write(f"HASH: {hash}\n")
                            export_file.write(f"ALGORITHM: {hash_id.upper()}\n\n")

                except:
                    print(colorize_text("Error: Invalid input file", "red"))
                    exit()
            else:
                try:
                    hash_list = read_hashes_from_file(file)

                    init_banner()
                    print(colorize_text("\n                        [!] INFORMATION", "cyan"))
                    print(colorize_text("\nDATE:", "cyan", "bold")+colorize_text(f" {formatted_date_time}", "yellow"))
                    separator("cyan")
                    for hash in hash_list:

                        hash_id = detect_hash_type(hash)

                        
                        print(colorize_text("\nHASH:", "cyan", "bold")+colorize_text(f" {hash}", "yellow"))
                        print(colorize_text("\nTYPE:", "cyan", "bold")+colorize_text(f" {hash_id.upper()}", "yellow"))

                except:
                    print(colorize_text("Error: Invalid input file", "red"))
                    exit()
            
    elif compare:  

        if h1 != None and h2 != None:
            h1 = h1.lower()
            h2 = h2.lower()
        
        if file != None:
            print(colorize_text("Error: --file is not valid for --compare", "red"))
            syexit()
        elif directory != None:
            print(colorize_text("Error: --dir is not valid for --compare", "red"))
            syexit()
        elif hash != None:
            print(colorize_text("Error: --hash is not valid for --compare", "red"))
            syexit()
        elif wordlist != None:
            print(colorize_text("Error: --wordlist is not valid for --compare", "red"))
            syexit()
        elif export != None:
            print(colorize_text("Error: --oN is not valid for --compare", "red"))
            syexit()
        elif algorithm != None:
            print(colorize_text("Error: --algorithm is not valid for --compare", "red"))
            syexit()
        elif block_size != None:
            print(colorize_text("Error: --block_size is not valid for --compare", "red"))
            syexit()
        elif h1 == None and h2 == None:
            print(colorize_text("Error: You need to add -h1 and -h2", "red"))
            syexit()
        elif h1 != None and h2 != None:

            if not is_hash(h1) and not is_hash(h2):
                print(colorize_text("Error: You need to use a hash in --h1 and --h2", "red"))
                syexit()
            elif not is_hash(h1):
                print(colorize_text("Error: You need to use a hash in --h1", "red"))
                syexit()
            elif not is_hash(h2):
                print(colorize_text("Error: You need to use a hash in --h2", "red"))
                syexit()

            else:
                
                

                if h1 == h2:

                    init_banner()
                    print(colorize_text("\nHASH 1:", "cyan", "bold")+colorize_text(f" {h1}", "green"))
                    print(colorize_text("\nHASH 2:", "cyan", "bold")+colorize_text(f" {h2}", "green"))
                    print(colorize_text("\nRESULT:", "cyan", "bold")+colorize_text(f" MATCH", "green", "bold"))
                
                else:

                    init_banner()
                    print(colorize_text("\nHASH 1:", "cyan", "bold")+colorize_text(f" {h1}", "yellow"))
                    print(colorize_text("\nHASH 2:", "cyan", "bold")+colorize_text(f" {h2}", "yellow"))
                    print(colorize_text("\nRESULT:", "cyan", "bold")+colorize_text(f" UNMATCH", "red", "bold"))
                    diff_positions = [i for i, (c1, c2) in enumerate(zip(h1, h2)) if c1 != c2]

        
                    marked_h1 = ''.join(colorize_text(c, "red", "bold") if i in diff_positions else colorize_text(c, "yellow") for i, c in enumerate(h1))
                    marked_h2 = ''.join(colorize_text(c, "red", "bold") if i in diff_positions else colorize_text(c, "yellow") for i, c in enumerate(h2))

                    print(colorize_text("\nMARKED HASH 1:", "cyan", "bold") + colorize_text(f" {marked_h1}", "yellow"))
                    print(colorize_text("\nMARKED HASH 2:", "cyan", "bold") + colorize_text(f" {marked_h2}", "yellow"))

    elif decrypt:

        if num_p == None:
            num_p = 3

        if block_size != None:
            print(colorize_text("Error: --block_size is not valid for --decrypt", "red"))
            syexit()
        elif file != None:
            print(colorize_text("Error: --file is not valid for --decrypt", "red"))
            syexit()
        elif h1 != None:
            print(colorize_text("Error: --h1 is not valid for --decrypt", "red"))
            syexit()
        elif h2 != None:
            print(colorize_text("Error: --h2 is not valid for --decrypt", "red"))
            syexit()
        
        elif wordlist == None:
            print(colorize_text("Error: --decrypt need a wordlist", "red"))
            syexit()

        
        elif hash == None:
            print(colorize_text("Error: --decrypt need a --hash", "red"))
            syexit()

        else:


            if export == None:


                hash_type = detect_hash_type(hash)
                hash_type = hash_type.lower()
                if hash_type == "unknown hash type":
                    print(colorize_text("Error: Unknown hash type", "red"))
                    syexit()
                try:
                    target_hash = hash
                    num_processes = num_p
                    target_hash = target_hash.lower()
                    result = parallel_hash_crack(hash_type, target_hash, wordlist, num_processes)
                    init_banner()
                    print(colorize_text("\n                        [!] INFORMATION", "cyan"))
                    print(colorize_text("\nDATE:", "cyan", "bold")+colorize_text(f" {formatted_date_time}", "yellow"))
                    print(colorize_text("\nWORDLIST:", "cyan", "bold")+colorize_text(f" {wordlist}", "yellow"))
                    print(colorize_text("\nHASH:", "cyan", "bold")+colorize_text(f" {hash}", "yellow"))
                    print(colorize_text("\nTYPE:", "cyan", "bold")+colorize_text(f" {hash_type.upper()}", "yellow"))
                    if result != None:
                        print(colorize_text("\nDECRYPTED:", "cyan", "bold")+colorize_text(f" {result}", "green", "bold"))
                    else:
                        print(colorize_text("\nDECRYPTED:", "cyan", "bold")+colorize_text(f" NO MATCH", "red", "bold"))
                    separator("cyan")
                except:
                    print(colorize_text("Error: Problem decrypting hash", "red"))
                    syexit()
            else:

                hash_type = detect_hash_type(hash)
                hash_type = hash_type.lower()
                if hash_type == "unknown hash type":
                    print(colorize_text("Error: Unknown hash type", "red"))
                    syexit()
                try:
                    target_hash = hash
                    num_processes = num_p
                    target_hash = target_hash.lower()
                    result = parallel_hash_crack(hash_type, target_hash, wordlist, num_processes)
                    init_banner()
                    print(colorize_text("\n                        [!] INFORMATION", "cyan"))
                    print(colorize_text("\nDATE:", "cyan", "bold")+colorize_text(f" {formatted_date_time}", "yellow"))
                    print(colorize_text("\nWORDLIST:", "cyan", "bold")+colorize_text(f" {wordlist}", "yellow"))
                    print(colorize_text("\nHASH:", "cyan", "bold")+colorize_text(f" {hash.lower()}", "yellow"))
                    print(colorize_text("\nTYPE:", "cyan", "bold")+colorize_text(f" {hash_type.upper()}", "yellow"))
                    if result != None:
                        print(colorize_text("\nDECRYPTED:", "cyan", "bold")+colorize_text(f" {result}", "green", "bold"))
                    else:
                        print(colorize_text("\nDECRYPTED:", "cyan", "bold")+colorize_text(f" NO MATCH", "red", "bold"))
                    separator("cyan")
                    with open(f"{export_path}", "w") as export_file:
                                    
                                export_file.write("##############################")
                                export_file.write("\n##          REPORT          ##")
                                export_file.write("\n##############################\n\n")
                                export_file.write(f"DATE: {formatted_date_time}\n\n")
                                export_file.write(f"ALGORITHM: {hash_type.upper()}\n\n")
                                export_file.write(f"HASH: {hash.lower()}\n\n")
                                export_file.write(f"DECRYPTED: {result}\n\n")
                except:
                    print(colorize_text("Error: Problem decrypting hash", "red"))
                    syexit()

    elif encrypt:

        if block_size != None:
            print(colorize_text("Error: --block_size is not valid for --encrypt", "red"))
            syexit()
        elif directory != None:
            print(colorize_text("Error: --dir is not valid for --encrypt", "red"))
            syexit()
        elif h1 != None:
            print(colorize_text("Error: --h1 is not valid for --encrypt", "red"))
            syexit()
        elif h2 != None:
            print(colorize_text("Error: --h2 is not valid for --encrypt", "red"))
            syexit()
        elif wordlist != None:
            print(colorize_text("Error: --wordlist is not valid for --encrypt", "red"))
            syexit()
        elif wordlist != None:
            print(colorize_text("Error: -p is not valid for --encrypt", "red"))
            syexit()
        elif hash != None:
            print(colorize_text("Error: --hash is not valid for --encrypt", "red"))
            syexit()
        elif file == None and string == None:
            print(colorize_text("Error: --encrypt need --file or --string", "red"))
            syexit()
        elif algorithm == None:
            print(colorize_text("Error: --encrypt need --algorithm", "red"))
            syexit()


        if file != None and string == None and algorithm != None:

            if export == None:
                algorithm = is_valid_hash_type(algorithm)
                if algorithm == "error":
                    print(colorize_text("Error: Invalid hash type (--algorithm)", "red"))
                    syexit()
                init_banner()
                print(colorize_text("\n                        [!] INFORMATION", "cyan", "bold"))
                print(colorize_text("\nDATE:", "cyan", "bold")+colorize_text(f" {formatted_date_time}", "yellow"))
                print(colorize_text("\nALGORITHM:", "cyan", "bold")+colorize_text(f" {algorithm.upper()}", "yellow"))
                separator("cyan")


                with open(file, "r") as file_in:

                    for line in file_in:
                        line = line.strip()
                        

                        if line:
                            result = get_hash_as_string(algorithm, line)
                            
                            

                            print(colorize_text("\nSTRING:", "cyan", "bold")+colorize_text(f" {line}", "yellow"))
                            print(colorize_text("\nHASH:", "cyan", "bold")+colorize_text(f" {result}", "yellow"))
                            separator("cyan")




            elif export != None:
                algorithm = is_valid_hash_type(algorithm)
                if algorithm == "error":
                    print(colorize_text("Error: Invalid hash type (--algorithm)", "red"))
                    syexit()
                init_banner()
                print(colorize_text("\n                        [!] INFORMATION", "cyan", "bold"))
                print(colorize_text("\nDATE:", "cyan", "bold")+colorize_text(f" {formatted_date_time}", "yellow"))
                print(colorize_text("\nFILE:", "cyan", "bold")+colorize_text(f" {file}", "yellow"))
                print(colorize_text("\nALGORITHM:", "cyan", "bold")+colorize_text(f" {algorithm.upper()}", "yellow"))
                separator("cyan")
                with open(f"{export_path}", "w") as export_file:
                        export_file.write("##############################")
                        export_file.write("\n##          REPORT          ##")
                        export_file.write("\n##############################\n\n")
                        export_file.write(f"DATE: {formatted_date_time}\n\n")
                        export_file.write(f"ALGORITHM: {algorithm.upper()}\n\n")


                with open(file, "r") as file_in:

                    for line in file_in:
                        line = line.strip()
                        

                        if line:
                            result = get_hash_as_string(algorithm, line)
                            
                            

                            print(colorize_text("\nSTRING:", "cyan", "bold")+colorize_text(f" {line}", "yellow"))
                            print(colorize_text("\nHASH:", "cyan", "bold")+colorize_text(f" {result}", "yellow"))
                            separator("cyan")
                            with open(f"{export_path}", "a") as export_file:
                                export_file.write(f"STRING: {line}\n")
                                export_file.write(f"HASH: {result}\n\n")




        elif file == None and string != None and algorithm != None:
            

            if export != None:
                algorithm = is_valid_hash_type(algorithm)
                if algorithm == "error":
                    print(colorize_text("Error: Invalid hash type (--algorithm)", "red"))
                    syexit()
                init_banner()
                result = get_hash_as_string(algorithm, string)
                print(colorize_text("\n                        [!] INFORMATION", "cyan", "bold"))
                print(colorize_text("\nDATE:", "cyan", "bold")+colorize_text(f" {formatted_date_time}", "yellow"))
                print(colorize_text("\nSTRING:", "cyan", "bold")+colorize_text(f" {string}", "yellow"))
                print(colorize_text("\nALGORITHM:", "cyan", "bold")+colorize_text(f" {algorithm.upper()}", "yellow"))
                print(colorize_text("\nHASH:", "cyan", "bold")+colorize_text(f" {result}", "yellow"))
                separator("cyan")
                with open(f"{export_path}", "w") as export_file:
                        export_file.write("##############################")
                        export_file.write("\n##          REPORT          ##")
                        export_file.write("\n##############################\n\n")
                        export_file.write(f"DATE: {formatted_date_time}\n\n")
                        export_file.write(f"STRING: {string}\n\n")
                        export_file.write(f"ALGORITHM: {algorithm.upper()}\n\n")
                        export_file.write(f"HASH: {result}\n\n")

            elif export == None:
                algorithm = is_valid_hash_type(algorithm)
                if algorithm == "error":
                    print(colorize_text("Error: Invalid hash type (--algorithm)", "red"))
                    syexit()
                init_banner()
                result = get_hash_as_string(algorithm, string)
                print(colorize_text("\n                        [!] INFORMATION", "cyan", "bold"))
                print(colorize_text("\nDATE:", "cyan", "bold")+colorize_text(f" {formatted_date_time}", "yellow"))
                print(colorize_text("\nSTRING:", "cyan", "bold")+colorize_text(f" {string}", "yellow"))
                print(colorize_text("\nALGORITHM:", "cyan", "bold")+colorize_text(f" {algorithm.upper()}", "yellow"))
                print(colorize_text("\nHASH:", "cyan", "bold")+colorize_text(f" {result}", "yellow"))
                separator("cyan")




        elif file != None and string != None and algorithm != None:
            print(colorize_text("Error: --encrypt need only --file or --string, not both", "red"))
            syexit()

if __name__ == "__main__":
# Parse command line arguments
    parser = argparse.ArgumentParser(description="HashGen - Hash Toolkit")
    group_main = parser.add_mutually_exclusive_group(required=True)


    group_main.add_argument('--calculate', action='store_true', help="Calculation Mode")
    group_main.add_argument('--id-hash', action='store_true', help="Identification Mode")
    group_main.add_argument('--compare', action='store_true', help="Compare Mode")
    group_main.add_argument('--encrypt', action='store_true', help="Decrypt Mode")
    group_main.add_argument('--decrypt', action='store_true', help="Decrypt Mode")


    parser.add_argument("--file", required=False, help="Path to the file", type=str)
    parser.add_argument("--dir", required=False, help="Path to the directory", type=str)
    parser.add_argument("-oN", required=False, help="Export the file (Name with extension)", type=str)
    parser.add_argument("--hash", required=False, help="Hash to analyze", type=str)



    parser.add_argument("--algorithm", required=False, help="Hash algorithm to use (Default SHA256)", type=str)
    parser.add_argument("--block-size", required=False, help="Block Size", type=int)
    


    parser.add_argument("-p", required=False, help="Number of processes to decrypt", type=int)
    parser.add_argument("--wordlist", required=False, help="Path to the wordlist (Only .txt)", type=str)

    parser.add_argument("--string", required=False, help="String to encrypt", type=str)

    parser.add_argument("-h1", required=False, help="Hash 1 to Compare", type=str)
    parser.add_argument("-h2", required=False, help="Hash 2 to Compare", type=str)

    
    args = parser.parse_args()

# Extract values from command line arguments

    calculate = args.calculate
    id_hash = args.id_hash
    compare = args.compare
    encrypt = args.encrypt
    decrypt = args.decrypt


    file = args.file
    directory = args.dir
    export = args.oN
    hash = args.hash

    algorithm = args.algorithm
    block_size = args.block_size
    
    wordlist = args.wordlist
    num_p = args.p

    h1 = args.h1
    h2 = args.h2

    string = args.string


    
 # Call the main function with extracted arguments
    main(calculate, id_hash, compare, decrypt, encrypt, file, directory, export, hash, algorithm, block_size, wordlist, h1, h2, num_p, string)
