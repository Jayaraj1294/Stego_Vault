# encode.py
# This module provides functionality to encode a secret message into an image using LSB steganography.

import cv2
import numpy as np
from .utility import text_to_binary

def encode_image(image_path, secret_message, output_path):
    """
    Encodes a secret message into an image using the least significant bit (LSB) method.

    :param image_path: Path to the input image.
    :param secret_message: The message to hide within the image.
    :param output_path: Path to save the encoded image.
    :raises ValueError: If the image cannot be opened or the message is too large.
    """
    
    # Load the image
    image = cv2.imread(image_path)
    if image is None:
        raise ValueError("Error: Image not found or could not be opened.")

    # Convert the message to binary and add a delimiter
    binary_message = text_to_binary(secret_message) + '1111111111111110'  # Delimiter (16-bit)
    data_index = 0
    total_pixels = image.shape[0] * image.shape[1] * 3  # Total number of color values in image
    
    # Check if the message fits in the image
    if len(binary_message) > total_pixels:
        raise ValueError("Error: Message too large to encode in the given image.")

    # Embed the binary message into the image
    for row in image:
        for pixel in row:
            for channel in range(3):  # Iterate over R, G, B channels
                if data_index < len(binary_message):
                    pixel[channel] = (pixel[channel] & 0xFE) | int(binary_message[data_index])
                    data_index += 1
                else:
                    break

    # Save the modified image
    cv2.imwrite(output_path, image)
    print(f"Message encoded successfully into {output_path}")


