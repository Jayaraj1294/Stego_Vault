from django.db import models
import hashlib
from django.utils.timezone import now

# User Registration table
class UserRegistration(models.Model):
    username = models.CharField(max_length=255, null=True)
    email = models.EmailField(null=True)
    password = models.CharField(max_length=255, null=True)
    bio = models.TextField(blank=True, null=True)
    purpose = models.TextField(blank=True, null=True)
    profile_picture = models.ImageField(upload_to='profile_pics/', default='default.jpg', blank=True)
    
    def __str__(self):
        return f"User {self.id} - {self.username or 'Unnamed'}"
    
# User Login-history table
class UserloginHistory(models.Model):
    user = models.ForeignKey(UserRegistration, on_delete=models.CASCADE)
    login_time = models.DateTimeField(auto_now_add=True)
    ip_address = models.GenericIPAddressField(null=True, blank=True)
    LOGIN_STATUS = [
        ('SUCCESS', 'Successfull Login'),
        ('Failed', 'Failed Login')
    ]
    status = models.CharField(max_length=20, choices=LOGIN_STATUS,null=True, blank=True)

    def __str__(self):
        return f"{self.user} - {self.status} at {self.login_time}"
    
# User Activity-log table
class UserActivityLog(models.Model):
    user = models.ForeignKey(UserRegistration, on_delete=models.CASCADE)
    action = models.CharField(max_length=255)
    timestamp = models.DateTimeField(default=now)

    def __str__(self):
        return f"{self.user.username} - {self.action} at {self.timestamp}"
    
# Notification table
class Notification(models.Model):
    user = models.ForeignKey(UserRegistration, on_delete=models.CASCADE)
    message = models.TextField()
    timestamp = models.DateTimeField(default=now)
    is_read = models.BooleanField(default=False)

    def __str__(self):
        return f"{self.user.username} - {self.message[:50]}"  # Display first 50 characters of the message

# Image upload and Watermark embed table
class UploadedImage(models.Model):
    user=models.ForeignKey(UserRegistration,on_delete=models.CASCADE,default="5")
    original_image = models.ImageField(upload_to='images/')
    watermark_logo = models.ImageField(upload_to='logos/',null=True, blank=True)
    watermark_text = models.CharField(max_length=255, blank=True, null=True)
    watermarked_image = models.ImageField(upload_to='watermarked_images/',null=True, blank=True)
    created_at = models.DateTimeField(default=now)  # Automatically sets the timestamp

    watermark_position = models.CharField(
    max_length=20,
    choices=[('top-left', 'Top Left'), ('top-right', 'Top Right'),
             ('center', 'Center'), ('bottom-left', 'Bottom Left'),
             ('bottom-right', 'Bottom Right')],
    default='bottom-right'
    )

    original_hash = models.CharField(max_length=256, blank=True, null=True) # SHA-256 Hash of the original image
    
    
    def __str__(self):
        return f"Image {self.id} with Watermark"
    
    def save(self, *args, **kwargs):
        if not self.original_hash and self.original_image:
            self.original_hash = self.compute_hash(self.original_image)
        super().save(*args, **kwargs)

    def compute_hash(self, image_field):
        """Compute SHA-256 hash of the image"""
        hasher = hashlib.sha256()
        for chunk in image_field.file.chunks():
            hasher.update(chunk)
        return hasher.hexdigest()
    
# Steganography Image encoding table
class EncodedImage(models.Model):
    original_image = models.ForeignKey(UploadedImage, on_delete=models.CASCADE)
    encoded_image = models.ImageField(upload_to='encoded_images/')
    secret_data = models.TextField()
    encoded_hash = models.CharField(max_length=256, blank=True, null=True)

    def save(self, *args, **kwargs):
        if not self.encoded_hash and self.encoded_image:
            self.encoded_hash = self.compute_hash(self.encoded_image)
        super().save(*args, **kwargs)

    def compute_hash(self, image_field):
        """Compute SHA-256 hash of the image"""
        hasher = hashlib.sha256()
        for chunk in image_field.file.chunks():
            hasher.update(chunk)
        return hasher.hexdigest()   

# Text encryption table
class EncryptedMessage(models.Model):
    title = models.CharField(max_length=255, default="Untitled Message")
    encrypted_aes_key = models.BinaryField() # AES key encrypted with RSA
    cipher_text = models.BinaryField() # Enrypted message
    nonce = models.BinaryField()
    tag = models.BinaryField()
    created_at = models.DateTimeField(auto_now_add=True) #Timestamp
    userid = models.ForeignKey(UserRegistration, on_delete=models.CASCADE,default="1")
    

    def __str__(self):
        return f"Message {self.id} - {self.title}"
    
# Watemark key and hashing table
class WatermarkKey(models.Model):
    image = models.OneToOneField(UploadedImage, on_delete=models.CASCADE, related_name='watermark_key')  # Ensure one key per image
    encrypted_aes_key = models.BinaryField() # Store AES key with RSA
    iv = models.BinaryField()
    created_at = models.DateTimeField(auto_now_add=True)
    watermarked_hash = models.CharField(max_length=256, blank=True, null=True)

    def save(self, *args, **kwargs):
        if not self.watermarked_hash and self.image.watermarked_image:
            self.watermarked_hash = self.compute_hash(self.image.watermarked_image)
        super().save(*args, **kwargs)

    def compute_hash(self, image_field):
        """Compute SHA-256 hash of the image"""
        hasher = hashlib.sha256()
        for chunk in image_field.file.chunks():
            hasher.update(chunk)
        return hasher.hexdigest()

    def __str__(self):
        return f"Key for image {self.image.id}"
    
class TamperingDetection(models.Model):
    uploaded_image = models.ForeignKey(UploadedImage, on_delete=models.CASCADE, null=True, blank=True)
    encoded_image = models.ForeignKey(EncodedImage, on_delete=models.CASCADE, null=True, blank=True)
    tampering_check_hash = models.CharField(max_length=256, blank=True, null=True) # SHA-256 Hash of the uploaded image
    detected_at = models.DateTimeField(auto_now_add=True)
    status = models.CharField(max_length=50, choices=[('original', 'Original'),('watermarked','Watermarked'),('steganographed','Steganographed')],
                              default='Not Verified')
    
    def __str__(self):
        return f"Tampering check for Image {self.uploaded_image.id} - Status: {self.status}"