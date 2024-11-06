import os
import subprocess
import hashlib
import base64
import argparse
from cryptography.fernet import Fernet
from stegano import lsb

# Checks if the specified file exists on the filesystem
def check_file_exists(file):
    if not os.path.isfile(file):
        return f"Error: {file} does not exist."
    return None

# Runs ExifTool commands for reading, writing, or stripping metadata
def run_exiftool(file, tag=None, value=None):
    try:
        if tag is None and value is None:
            result = subprocess.run(['exiftool', file], capture_output=True, text=True)
        elif tag and value:
            result = subprocess.run(['exiftool', f'-{tag}={value}', file], capture_output=True, text=True)
        else:
            return "Error: Missing tag or value for writing metadata."
        return result.stdout if result.returncode == 0 else result.stderr
    except Exception as e:
        return f"Error running exiftool: {str(e)}"

# Derives a 32-byte encryption key from a passphrase, used for encrypting/decrypting messages with Fernet
def derive_key_from_passphrase(passphrase):
    key = hashlib.sha256(passphrase.encode()).digest()
    return base64.urlsafe_b64encode(key[:32])

# Encrypts the message with a passphrase using Fernet encryption
def encrypt_message(message, passphrase):
    key = derive_key_from_passphrase(passphrase)
    cipher = Fernet(key)
    encrypted_message = cipher.encrypt(message.encode())
    return encrypted_message

# Decrypts an encrypted message using the passphrase
def decrypt_message(encrypted_message, passphrase):
    try:
        key = derive_key_from_passphrase(passphrase)
        cipher = Fernet(key)
        decrypted_message = cipher.decrypt(encrypted_message).decode()
        return decrypted_message
    except Exception as e:
        return "Error: Incorrect passphrase or corrupted message."

# Reads and displays metadata from a specified image file
def read_metadata(file):
    error = check_file_exists(file)
    if error:
        return error
    output = run_exiftool(file)
    if "Error" in output:
        return "Failed to read metadata. Check if the file is valid."
    return output

# Removes all metadata from a specified image file
def strip_metadata(file):
    error = check_file_exists(file)
    if error:
        return error
    result = subprocess.run(['exiftool', '-all=', file], capture_output=True, text=True)
    return result.stdout if result.returncode == 0 else result.stderr

# Writes or modifies a specified metadata tag in an image file ('tag' is the metadata field and 'value' is the new value for the tag)
def write_metadata(file, tag, value):
    error = check_file_exists(file)
    if error:
        return error
    if isinstance(value, list):
        value = ' '.join(value)
    return run_exiftool(file, tag, value)

# Embeds a hidden message into an image file with optional encryption if a passphrase is provided and saves the image with the embedded message to 'output_file'
def embed_message(file, message, output_file, passphrase=None):
    error = check_file_exists(file)
    if error:
        return error
    if not is_supported_image_format(file):
        return "Error: Steganography works best with PNG or BMP formats."
    if isinstance(message, list):
        message = ' '.join(message)
    if passphrase:
        message = encrypt_message(message, passphrase)
        message = message.decode()
    secret = lsb.hide(file, message)
    secret.save(output_file)
    return f"Message embedded into {output_file}"

# Extracts a hidden message from an image file with optional decryption if it was encrypted during embedding
def extract_message(file, passphrase=None):
    error = check_file_exists(file)
    if error:
        return error
    message = lsb.reveal(file)
    if not message:
        return "No hidden message found."
    if passphrase:
        try:
            message = decrypt_message(message.encode(), passphrase)
        except Exception as e:
            return f"Error decrypting message: {str(e)}"
    return message

# Checks if the image file format is supported for steganography (supported formats are PNG and BMP, JPEG is not supported due to compression)
def is_supported_image_format(file):
    return file.lower().endswith(('.png', '.bmp'))

# Processes each image file in a specified directory based on the given action (reading, stripping, writing metadata, embedding, and extracting messages)
def process_directory(directory, action, *args, save_file=None):
    output_data = []
    for root, _, files in os.walk(directory):
        for file in files:
            if file.lower().endswith(('.jpg', '.jpeg', '.png', '.bmp')):
                file_path = os.path.join(root, file)
                if action == "strip":
                    result = strip_metadata(file_path)
                    print(result)
                    output_data.append(f"{file_path}:\n{result}")
                elif action == "read":
                    result = read_metadata(file_path)
                    print(result)
                    output_data.append(f"{file_path}:\n{result}")
                elif action == "write":
                    result = write_metadata(file_path, *args)
                    print(result)
                    output_data.append(f"{file_path}:\n{result}")
                elif action == "embed":
                    result = embed_message(file_path, *args)
                    print(result)
                    output_data.append(f"{file_path}:\n{result}")
                elif action == "extract":
                    result = extract_message(file_path, *args)
                    print(result)
                    output_data.append(f"{file_path}:\n{result}")
    if save_file and output_data:
        save_metadata_to_file(save_file, "\n\n".join(output_data))

# Saves the extracted metadata output to a text file
def save_metadata_to_file(file, output):
    with open(file, 'w') as f:
        f.write(output)
    print(f"Metadata saved to {file}")

# Main function to parse command-line arguments and execute appropriate commands
def main():
    parser = argparse.ArgumentParser(description="PicMetaStegSec - CLI wrapper for ExifTool with steganography and encryption")
    # Define subcommands for different functionalities
    subparsers = parser.add_subparsers(dest="command", help="Available commands")
    # Subcommand for reading metadata
    parser_read = subparsers.add_parser("read", help="Read Exif metadata from an image or directory")
    parser_read.add_argument("file", help="Path to the image file or directory to read metadata from")
    parser_read.add_argument("--save", help="Save the metadata output to the specified file", default=None)
    # Subcommand for stripping metadata
    parser_strip = subparsers.add_parser("strip", help="Remove all Exif metadata from an image or directory")
    parser_strip.add_argument("file", help="Path to the image file or directory to strip metadata from")
    # Subcommand for writing/editing metadata
    parser_write = subparsers.add_parser("write", help="Write or edit Exif metadata in an image or directory")
    parser_write.add_argument("file", help="Path to the image file or directory to write metadata to")
    parser_write.add_argument("tag", help="Metadata tag to modify (e.g., 'comment')")
    parser_write.add_argument("value", nargs='+', help="Value to set for the specified metadata tag")
    parser_write.add_argument("--save", help="Save the modified metadata details to the specified file", default=None)
    # Subcommand for embedding a hidden message
    parser_embed = subparsers.add_parser("embed", help="Embed a hidden message into an image with optional encryption")
    parser_embed.add_argument("file", help="Path to the image file for embedding the message")
    parser_embed.add_argument("message", nargs='+', help="Message to embed into the image")
    parser_embed.add_argument("output_file", help="Path to save the output image with the embedded message")
    parser_embed.add_argument("--passphrase", help="Passphrase to encrypt the hidden message (optional)", default=None)
    # Subcommand for extracting a hidden message
    parser_extract = subparsers.add_parser("extract", help="Extract a hidden message from an image with optional decryption")
    parser_extract.add_argument("file", help="Path to the image file to extract the hidden message from")
    parser_extract.add_argument("--passphrase", help="Passphrase to decrypt the hidden message (optional)", default=None)
    # Parses arguments and executes commands
    args = parser.parse_args()
    if args.command == "read":
        if os.path.isdir(args.file):
            process_directory(args.file, "read", save_file=args.save)
        else:
            output = read_metadata(args.file)
            print(output)
            if args.save:
                save_metadata_to_file(args.save, output)
    elif args.command == "strip":
        if os.path.isdir(args.file):
            process_directory(args.file, "strip", save_file=args.save)
        else:
            print(strip_metadata(args.file))
    elif args.command == "write":
        if os.path.isdir(args.file):
            process_directory(args.file, "write", args.tag, args.value, save_file=args.save)
        else:
            print(write_metadata(args.file, args.tag, args.value))
    elif args.command == "embed":
        print(embed_message(args.file, args.message, args.output_file, args.passphrase))
    elif args.command == "extract":
        print(extract_message(args.file, args.passphrase))

# Executes the main function if the script is run as the main program
if __name__ == "__main__":
    main()
