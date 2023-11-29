import hashlib
from modules.style_and_banners import *
from sys import exit as syexit
from os import path, walk
from re import compile, match

# Function to calculate the hash of a file
def calculate_file_hash(path, algorithm, block_size):

    if algorithm == "sha1":
        hash_calculated = hashlib.sha1()
    elif algorithm == "sha224":
        hash_calculated = hashlib.sha224()
    elif algorithm == "sha256":
        hash_calculated = hashlib.sha256()
    elif algorithm == "sha384":
        hash_calculated = hashlib.sha384()
    elif algorithm == "sha512":
        hash_calculated = hashlib.sha512()
    elif algorithm == "md5":
        hash_calculated = hashlib.md5()
    else:
        print(colorize_text("Error: Invalid algorithm", "red"))
        syexit()

    # Calculate the file hash in blocks
    with open(path, 'rb') as file:
        for block in iter(lambda: file.read(block_size), b''):
            hash_calculated.update(block)
            

    # Return the hash in hexadecimal format
    return hash_calculated.hexdigest()

# Function to calculate the hash of a directory
def calculate_hashes_directory(directory,algorithm,block_size):
    hashes = {}

    # Traverse through all the files in the directory
    for root, _, files in walk(directory, block_size):
        for file in files:
            full_path = path.join(root, file)
            file_hash = calculate_file_hash(full_path, algorithm, block_size)
            hashes[full_path] = file_hash

    return hashes

# Function to detect a if a string is a hash
def is_hash(string):
    # Define expected lengths for different hash types
    expected_lengths = {
        'MD5': 32,
        'SHA-1': 40,
        'SHA-224': 56,
        'SHA-256': 64,
        'SHA-384': 96,
        'SHA-512': 128,
    }

    # Check if the string has a valid length for a known hash
    for algorithm, expected_length in expected_lengths.items():
        pattern = compile(rf'^[0-9a-fA-F]{{{expected_length}}}$')
        if pattern.match(string):
            return True

    return False

# Function to detect hash types
def detect_hash_type(hash_value):
    # Define the mapping of length to hash type
    hash_types = {
        32: 'MD5',
        40: 'SHA1',
        64: 'SHA256',
        128: 'SHA512',
        96: 'SHA384',
        56: 'SHA224',
    }

    # Get the length of the hash
    length = len(hash_value)

    # Check if the length is in the dictionary
    if length in hash_types and all(c in '0123456789abcdefABCDEF' for c in hash_value):
        return hash_types[length]

    # If it doesn't match any known type
    return 'Unknown hash type'

# Function to read hashes from a file
def read_hashes_from_file(file_name):
    try:
        with open(file_name, 'r') as file:
            return [line.strip() for line in file.readlines() if line.strip()]
    except FileNotFoundError:
        print(f"The file {file_name} was not found.")
        return []
