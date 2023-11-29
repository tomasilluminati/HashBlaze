import hashlib
import multiprocessing
from modules.style_and_banners import *


# Function to decrypt a hash
def hash_cracker(hash_type, target_hash, wordlist_chunk, result_queue):

    for word in wordlist_chunk:
        hashed_word = hashlib.new(hash_type, word.encode()).hexdigest()
        if hashed_word == target_hash:
            result_queue.put(word)
            return
    result_queue.put(None)

# Function that splits a wordlist into chunks for parallel processing
def split_wordlist(wordlist, num_processes):
    with open(wordlist, 'r', encoding='utf-8') as file:
        words = file.read().splitlines()

    if len(words) <= num_processes:

        return [words]

    chunk_size = len(words) // num_processes
    chunks = [words[i:i + chunk_size] for i in range(0, len(words), chunk_size)]
    return chunks

# Function that performs parallel hash cracking using multiprocessing
def parallel_hash_crack(hash_type, target_hash, wordlist, num_processes):
    wordlist_chunks = split_wordlist(wordlist, num_processes)
    result_queue = multiprocessing.Queue()

    processes = []
    for chunk in wordlist_chunks:
        process = multiprocessing.Process(target=hash_cracker, args=(hash_type, target_hash, chunk, result_queue))
        processes.append(process)

    for process in processes:
        process.start()

    for process in processes:
        process.join()

    results = [result_queue.get() for _ in processes]

    for result in results:
        if result:
            return result

# Function that encrypt a string
def get_hash_as_string(hash_type, input_string):
    # Create a hash object based on the specified hash type
    hash_object = hashlib.new(hash_type)
    
    # Update the hash with the provided string
    hash_object.update(input_string.encode('utf-8'))
    
    # Get the hash as a hexadecimal string
    hash_result = hash_object.hexdigest()
    
    return hash_result

# Fuction that detect if algorithm is valid
def is_valid_hash_type(algorithm):

    algorithm = algorithm.lower()

    if algorithm == "md5":
        algorithm = "md5"
    elif algorithm == "sha1" or algorithm == "sha-1":
        algorithm = "sha1"
    elif algorithm == "sha256" or algorithm == "sha-256":
        algorithm = "sha256"
    elif algorithm == "sha512" or algorithm == "sha-512":
        algorithm = "sha512"
    elif algorithm == "sha384" or algorithm == "sha-384":
        algorithm = "sha384"
    elif algorithm == "sha224" or algorithm == "sha-224":
        algorithm = "sha224"
    else:
        algorithm = "error"

    return algorithm

# Function    
def process_file(input_file, hash_type):
    try:
        with open(input_file, 'r', encoding='utf-8') as file:
            for line_number, line in enumerate(file, start=1):
                # Remove newline characters from each line
                line = line.strip()
                
                # Get the hash for the current line
                hash_result = get_hash_as_string(hash_type, line)
                
                # Print or use the hash result as needed
                print(f"Line {line_number}: {hash_type} of '{line}': {hash_result}")

    except FileNotFoundError:
        print(f"Error: File '{input_file}' not found.")
