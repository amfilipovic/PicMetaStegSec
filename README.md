# PicMetaStegSec

## Overview

The PicMetaStegSec (`PicMetaStegSec.py`) is a Python script designed to manage image metadata and perform steganography. It serves as a command-line wrapper for ExifTool to read, write, and strip metadata from images. Additionally, it allows users to embed and extract hidden messages in `.png` or `.bmp` files, with an optional layer of AES encryption using a passphrase. It can process single files or entire directories.

## Files

1. `PicMetaStegSec.py`: The main script containing all logic for metadata manipulation and steganography.
2. `[output_file].png`: (User-defined) Output image file created when embedding a message.
3. `[output_file].txt`: (User-defined) Optional output file when saving metadata from the `read` command.

## Dependencies

- Python standard libraries:
  - `argparse`
  - `os`
  - `subprocess`
  - `hashlib`
  - `base64`
- External libraries:
  - `cryptography` (for encryption/decryption)
  - `stegano` (for steganography)
- External tools:
  - **ExifTool**: This tool is required and must be installed and accessible in your system's PATH for all metadata functions (read, write, strip).

## Functions and Logic

### `run_exiftool`

- **Purpose:** A wrapper to execute ExifTool commands safely.
- **Logic:**
  - Uses `subprocess.run` to call the `exiftool` executable.
  - Can read all tags (no arguments), write a tag (`-tag=value`), or strip all tags (`-all=`).

### `encrypt_message` / `decrypt_message`

- **Purpose:** To secure hidden messages with a passphrase.
- **Logic:**
  - Derives a 32-byte key from the user's passphrase using `hashlib.sha256`.
  - Uses the `cryptography.fernet` library (AES-128-CBC) to encrypt or decrypt the message text.

### `embed_message` / `extract_message`

- **Purpose:** Hides or reveals a message within an image file.
- **Logic:**
  - Uses `stegano.lsb.hide` to embed the message and `stegano.lsb.reveal` to extract it.
  - Before embedding, it optionally calls `encrypt_message` if a passphrase is provided.
  - After extracting, it optionally calls `decrypt_message`.
  - Checks for supported formats (`.png`, `.bmp`).

### `process_directory`

- **Purpose:** Applies a chosen action to all supported images in a directory.
- **Logic:**
  - Uses `os.walk` to find all files in the given directory.
  - For each file, it checks the extension and calls the appropriate function (e.g., `strip_metadata`, `read_metadata`).

### `main`

- **Purpose:** Handles user input and directs traffic to other functions.
- **Logic:**
  - Uses `argparse` with `subparsers` to create distinct commands (`read`, `write`, `strip`, `embed`, `extract`).
  - Parses command-line arguments and passes them to the correct functions.
  - Handles file vs. directory logic, sending directory paths to `process_directory`.

## Usage

The script uses subcommands to perform different actions: `read`, `write`, `strip`, `embed`, and `extract`.

### Command-line Arguments

#### `read`

| Argument | Description                                                |
| -------- | ---------------------------------------------------------- |
| `file`   | Path to the image file or directory to read metadata from. |
| `--save` | Save the metadata output to the specified text file.       |

#### `write`

| Argument | Description                                                         |
| -------- | ------------------------------------------------------------------- |
| `file`   | Path to the image file or directory to write metadata to.           |
| `tag`    | Metadata tag to modify (e.g., 'Comment', 'Artist').                 |
| `value`  | Value(s) to set for the specified tag.                              |
| `--save` | Save the operation log to the specified text file (directory mode). |

#### `strip`

| Argument | Description                                                 |
| -------- | ----------------------------------------------------------- |
| `file`   | Path to the image file or directory to strip metadata from. |

#### `embed`

| Argument       | Description                                           |
| -------------- | ----------------------------------------------------- |
| `file`         | Path to the input image file (e.g., .png, .bmp).      |
| `message`      | The message(s) to embed into the image.               |
| `output_file`  | Path to save the new image with the embedded message. |
| `--passphrase` | Optional passphrase to encrypt the hidden message.    |

#### `extract`

| Argument       | Description                                                |
| -------------- | ---------------------------------------------------------- |
| `file`         | Path to the image file to extract the hidden message from. |
| `--passphrase` | Optional passphrase to decrypt the hidden message.         |

### Running the script

Read metadata from a single file:

```sh
python PicMetaStegSec.py read example.jpg
```

Write a 'Comment' tag to a file:

```sh
python PicMetaStegSec.py write example.jpg Comment "This is a test image."
```

Strip all metadata from all images in a directory:

```sh
python PicMetaStegSec.py strip ./my_images/
```

Embed an encrypted message into a PNG file:

```sh
python PicMetaStegSec.py embed input.png "My secret message" output.png --passphrase "StrongPassword123"
```

Extract an encrypted message:

```sh
python PicMetaStegSec.py extract output.png --passphrase "StrongPassword123"
```

## Output

- **Standard Output (stdout)**: By default, the script prints results (read metadata, success/error messages) directly to the console.
- **Image Files**: The `embed` command creates a new image file. The `strip` and `write` commands modify the image file in-place (ExifTool often creates a `_original` backup).
- **Text Files**: Using the `--save` argument with the `read` or `write`/`strip` (in directory mode) commands saves the output log to a specified `.txt` file.

## Notes

- Steganography (embedding/extracting) is only supported for lossless image formats like **`.png`** and **`.bmp`**.
- Metadata functions (read, write, strip) work with any file type supported by ExifTool (e.g., JPEG, PNG, GIF, etc.).
- Providing an incorrect passphrase during extraction will result in an error or corrupted data.

## Contributions

Contributions are welcome\! Feel free to submit issues or pull requests to improve the tool.
