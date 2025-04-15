import hashlib

"""This computes the SHA-256 of the image file"""

def calculate_image_hash(image_file):
    hasher = hashlib.sha256()
    for chunk in image_file.chunks():
        hasher.update(chunk)
    return hasher.hexdigest()