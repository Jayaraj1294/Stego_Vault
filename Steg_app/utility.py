# utility.py
# This module contains utility functions for text and binary conversion.

def text_to_binary(text):
    """
    Converts a given text string into its binary representation.
    
    :param text: The input string to convert.
    :return: A string representing the binary form of the text.
    """
    return ''.join(format(ord(char), '08b') for char in text)

def binary_to_text(binary_data):
    """
    Converts a binary string back to text.
    
    :param binary_data: A string of binary digits.
    :return: The decoded text message.
    """
    chars = [binary_data[i:i+8] for i in range(0, len(binary_data), 8)]
    return ''.join(chr(int(char, 2)) for char in chars if int(char, 2) != 0)
