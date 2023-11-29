# HashGen - Hash Toolkit

![GitHub License](https://img.shields.io/badge/License-MIT-green) ![FuzzX Tool](https://img.shields.io/badge/Tool-Hash_Toolkit-blue)

## Overview

HashGen is a powerful command-line tool designed for a variety of hashing-related tasks. Whether you need to calculate hash values, identify hashes, compare hashes, or engage in encryption and decryption operations, HashGen has you covered.

## Table of Contents

- [Usage](#usage)
- [Features](#features)
- [License](#license)
- [Disclaimer](#disclaimer)

## Usage

To utilize HashGen, follow these steps:

1. Clone this repository to your local machine.

2. Run the tool using the following command:

   ```bash
   python3 hashgen.py [--calculate | --id-hash | --compare | --encrypt | --decrypt] [--file FILE] [--dir DIRECTORY] [-oN EXPORT] [--hash HASH] [--algorithm ALGORITHM] [--block-size BLOCK_SIZE] [-p NUM_PROCESSES] [--wordlist WORDLIST] [--string STRING] [-h1 HASH1] [-h2 HASH2]
   ```

3. Adjust the tool's settings to suit your needs and initiate the process.

## Command Line Arguments

- `--calculate`: Enter Calculation Mode.
- `--id-hash`: Enter Identification Mode.
- `--compare`: Enter Compare Mode.
- `--encrypt`: Enter Encrypt Mode.
- `--decrypt`: Enter Decrypt Mode.

### Common Options

- `--file FILE`: Path to the file.
- `--dir DIRECTORY`: Path to the directory.
- `-oN EXPORT`: Export the file (Name with extension).
- `--hash HASH`: Hash to analyze.
- `--algorithm ALGORITHM`: Hash algorithm to use (Default SHA256).

### Options for Calculate

- `--block-size BLOCK_SIZE`: Block Size.

### Options for Comparison

- `--h1 HASH1`: Hash 1 for comparison.
- `--h2 HASH2`: Hash 2 for comparison.

### Options for Decryption

- `-p NUM_PROCESSES`: Number of processes for decryption.
- `--wordlist WORDLIST`: Path to the wordlist (Only .txt).

### Options for Encryption 

- `--string STRING`: String to encrypt.

## Features

**1. Calculation Mode**

Calculate hash values for files using various algorithms. Specify the file path using the --file option.

**2. Identification Mode**

Identify the hash algorithm used for a given hash. Provide the hash value using the --hash option.

**3. Compare Mode**

Compare two hash values to check for similarity. Use the --h1 and --h2 options to provide the hash values for comparison.

**4. Encrypt Mode**

Encrypt a string using an unspecified encryption algorithm. Input the string using the --string option.

**5. Decrypt Mode**

Decrypt a hash using multiple processes and a specified wordlist. Utilize the -p option to set the number of processes. Specify the wordlist file using the --wordlist option.

## Disclaimer

This program is provided as-is, with no warranties of any kind. The author and the code provider assume ZERO responsibility for any direct or indirect damages that may arise from the use of this program.

By using this program, you acknowledge and accept this disclaimer of liability.

**Please ensure that you understand the code and its implications before using it. Always conduct thorough testing in a safe environment before implementing this code in a production setting.**

## License

**Copyright © 2023 Tomás Illuminati**

*This project is licensed under the [MIT License](LICENSE).*

*Visit our GitHub repository: [HashGen](https://github.com/tomasilluminati/HashGen)*
