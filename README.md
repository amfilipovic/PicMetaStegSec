# PicMetaStegSec

**PicMetaStegSec** is a command-line tool designed to manage image metadata, embed hidden messages, and secure them with encryption. It provides a flexible way to manipulate Exif metadata, apply steganography to hide messages within images, and protect sensitive data with encryption. This tool is particularly useful in educational contexts, but can be applied wherever image data security is needed.

## Features

- **Metadata Manipulation**: Read, strip, and write Exif metadata in images.
- **Steganography**: Embed hidden messages within images.
- **Encryption**: Encrypt hidden messages with a passphrase for added security.

## Installation

Ensure that Python is installed, along with the necessary libraries:

```sh
pip install cryptography stegano
```

## Usage

Below are some examples of how to use **PicMetaStegSec**.

### Metadata Operations

```sh
# Read metadata from a single image file
python PicMetaStegSec.py read image.jpg

# Read metadata from a directory of images and save the results to a file
python PicMetaStegSec.py read directory --save metadata.txt

# Strip all metadata from a single image file
python PicMetaStegSec.py strip image.jpg

# Strip all metadata from all images in a directory
python PicMetaStegSec.py strip directory

# Write or modify metadata in a single image file (e.g., the 'comment' tag)
python PicMetaStegSec.py write image.jpg comment "Example comment"

# Write or modify metadata in all images in a directory and save output to a file
python PicMetaStegSec.py write images_directory comment "Example comment" --save metadata.txt
```

### Steganography (Embedding and Extracting Messages)

```sh
# Embed a hidden message in an image and save the output to a new file
python PicMetaStegSec.py embed image.png "Hidden message" image_with_message.png

# Embed a hidden, encrypted message in an image, using a passphrase
python PicMetaStegSec.py embed image.png "Secret message" image_with_message.png --passphrase password

# Extract a hidden message from an image
python PicMetaStegSec.py extract image_with_message.png

# Extract and decrypt a hidden message from an image using a passphrase
python PicMetaStegSec.py extract image_with_message.png --passphrase password
```

## Contribution

Contributions are welcome! Feel free to submit issues or pull requests to improve the tool.
