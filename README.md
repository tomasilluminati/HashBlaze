# HashBlaze - Hash Toolkit

![GitHub License](https://img.shields.io/badge/License-MIT-green) ![FuzzX Tool](https://img.shields.io/badge/Tool-Hash_Toolkit-blue)

## Overview

HashBlaze is a powerful command-line tool designed for a variety of hashing-related tasks. Whether you need to calculate hash values, identify hashes, compare hashes, or engage in encryption and decryption operations, HashBlaze has you covered.

## Table of Contents

- [Usage](#usage)
- [Features](#features)
- [License](#license)
- [Disclaimer](#disclaimer)

## Usage

To utilize HashBlaze, follow these steps:

1. Clone this repository to your local machine.

2. Run the tool using the following command:

   ```bash
   python3 hashblaze.py [--calculate | --id-hash | --compare | --encrypt | --decrypt] [--file FILE] [--dir DIRECTORY] [-oN EXPORT] [--hash HASH] [--algorithm ALGORITHM] [--block-size BLOCK_SIZE] [-p NUM_PROCESSES] [--wordlist WORDLIST] [--string STRING] [-h1 HASH1] [-h2 HASH2]
   ```

3. Adjust the tool's settings to suit your needs and initiate the process.

## Command Line Arguments

- `--calculate`: Enter Calculation Mode.
- `--id-hash`: Enter Identification Mode.
- `--compare`: Enter Compare Mode.
- `--encrypt`: Enter Encrypt Mode.
- `--decrypt`: Enter Decrypt Mode.

### Common Options

- `--file`: Path to the file.
- `--dir`: Path to the directory.
- `-oN`: Export the file (Name with extension).
- `--hash`: Hash to analyze.
- `--algorithm`: Hash algorithm to use (Default SHA256).

### Options for Calculate

- `--block-size`: Block Size.

### Options for Comparison

- `--h1`: Hash 1 for comparison.
- `--h2`: Hash 2 for comparison.

### Options for Decryption

- `-p`: Number of processes for decryption (Default 3).
- `--wordlist`: Path to the wordlist (Only .txt files).

### Options for Encryption 

- `--string`: String to encrypt.

## Features

**1. Calculation Mode**

Calculate hash values for files using various algorithms. Specify the file path using the --file option, or the directory path using --dir, you can also select whether you want the type of algorithm (--algorithm) to calculate and you can export the result of the file or files with - -oN

Example:
- `python3 hashblaze.py --calculate --file ./myfile.txt --algorithm sha256 -oN export.txt | python3 hashblaze.py --calculate --dir ./my/path/to/dir/`

**2. Identification Mode**

Identify the hashing algorithm used for a given hash. Provide the hash value using the --hash option or the --file option to parse a text file. You can export the file with --oN

Example:
- `python3 hashblaze.py --id-hash --hash b10a8db164e0754105b7a99be72e3fe5 | python3 hashblaze.py --id-hash --file ./myfile.txt -oN export.txt`

**3. Compare Mode**

Compare two hash values to check similarity. Use the --h1 and --h2 options to provide hash values for comparison. --oN is not implemented for --compare

Example:
- `python3 hashblaze.py --compare -h1 b10a8db164e0754105b7a99be72e3fe5 --h2 b10a8db164e0754105b7a99be72e3fe5`

**4. Encrypt Mode**

Encrypt a string using an unspecified encryption algorithm. Enter the string using the --string option or the --file option to allow encryption of all lines of a .txt file. In addition, the type of algorithm with which it will be encrypted must be specified. You can then export the result with --oN

Example:
- `python3 hashblaze.py --encrypt --string "Hello World" --algorithm sha256 | python3 hashblaze.py --encrypt --file ./myfile.txt --algorithm sha256 -oN export.txt`

**5. Decrypt Mode**

Crack a hash using multiple processes and a specific word list. Use the -p option to set the number of processes (Default 3). Specify the wordlist file using the --wordlist option. Then specify a --hash to decrypt. Finally you can export the result with --oN

Example:
- `python3 hashblaze.py --decrypt --hash b10a8db164e0754105b7a99be72e3fe5 --wordlist ./word.txt --oN export.txt`

## Disclaimer

This program is provided as-is, with no warranties of any kind. The author and the code provider assume ZERO responsibility for any direct or indirect damages that may arise from the use of this program.

By using this program, you acknowledge and accept this disclaimer of liability.

**Please ensure that you understand the code and its implications before using it. Always conduct thorough testing in a safe environment before implementing this code in a production setting.**

## License

**Copyright © 2023 Tomás Illuminati**

*This project is licensed under the [MIT License](LICENSE).*

*Visit our GitHub repository: [HashBlaze](https://github.com/tomasilluminati/HashBlaze)*
