# decode.py
# This module provides functionality to extract a hidden message from an image.

import cv2
from .utility import binary_to_text

def decode_image(image_path):
    """
    Decodes a hidden message from an image using the least significant bit (LSB) method.

    :param image_path: Path to the encoded image.
    :return: The extracted hidden message.
    :raises ValueError: If the image cannot be opened.
    """
    
    # Load the image
    image = cv2.imread(image_path)
    if image is None:
        raise ValueError("Error: Image not found or could not be opened.")

    binary_message = ""

    # Extract the binary message from the image
    for row in image:
        for pixel in row:
            for channel in range(3):
                binary_message += str(pixel[channel] & 1)  # Extract LSB
                if binary_message[-16:] == '1111111111111110':  # Check for delimiter
                    return binary_to_text(binary_message[:-16])

    return binary_to_text(binary_message)  # Return decoded text if no delimiter is found

# # Example usage (uncomment to run)
# print(decode_image('output.png'))
