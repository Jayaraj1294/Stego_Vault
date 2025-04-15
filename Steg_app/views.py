from django.shortcuts import render, get_object_or_404, redirect
from django.core.files.storage import FileSystemStorage
from django.core.files.base import ContentFile
from django.conf import settings
from django.contrib.auth import logout, update_session_auth_hash
from .decorators import login_required
from django.contrib.auth.hashers import make_password, check_password
from django.contrib import messages
from django.http import JsonResponse, HttpResponse
from django.core.mail import send_mail
from django.utils.timezone import now, timedelta
from datetime import date
from django.db.models.functions import TruncDate
from django.contrib.messages import get_messages
from django.urls import reverse
from django.views.decorators.csrf import csrf_protect
from django.http import FileResponse, Http404
import os
import cv2
import numpy as np
from PIL import Image
import hashlib
from django.db.models import Q
from .models import *
from .crypto_utils import encrypt_message, decrypt_message
from .encode import encode_image
from .decode import decode_image
from .hash_utils import calculate_image_hash

# Index views
def index(request):
    return render(request,'index.html')

# Home views
def home(request):
    return render(request, 'home.html')

# Terms views
def Terms(request):
    return render(request, 'Terms.html')

# Privacy views
def Privacy(request):
    return render(request, 'Privacy.html')

# Contact Views
def contact(request):
    if request.method == "POST":
        name = request.POST.get("name")
        email = request.POST.get("email")
        subject = request.POST.get("subject")
        message = request.POST.get("message")

        if name and email and subject and message:
            # Send Email
            send_mail(
                subject=f"{subject}",
                message = f"Name: {name}\n Email: {email}\n\n Message: {message}",
                from_email=email,
                recipient_list=["jayuj6028@gmail.com"],
                fail_silently= False,
            )

            messages.success(request, "Your message has been sent successfully!")
            return redirect("contact")
        else:
            messages.error(request,"All fields are required")

    return render(request, 'home.html')

# Login views
def log(request):
    if request.method == "POST":
        email = request.POST.get("email")
        password = request.POST.get("password")
        ip_address = request.META.get("HTTP_X_FORWARDED_FOR", request.META.get("REMOTE_ADDR"))  # Capture IP

        user = UserRegistration.objects.filter(email=email).first()
        
        if user and check_password(password, user.password):
            # messages.success(request, f"Welcome, {user.username}!")
            request.session['userid']=user.id
            UserloginHistory.objects.create(user=user, status="Successfull Login", ip_address=ip_address, login_time=now())
            return redirect("dash")
        else:
            if user:  # If email exists but password is wrong
                UserloginHistory.objects.create(user=user, status="Failed Login", ip_address=ip_address, login_time=now())
            messages.error(request, "Invalid email or password!")
            return redirect("log")

    return render(request,'login.html')

#Forgot views
def forgot(request):
    if request.method == "POST":
        email = request.POST.get("email")
        try:
            user = UserRegistration.objects.get(email=email)
            user_id = user.id
            # Send email link in form of button
            reset_url = f"{settings.SITE_URL}/reset/{user_id}/"

            # Send mail
            send_mail(
                subject = "Password Reset Request",
                message="",
                html_message=f"""\n Click the button below to reset your password: \n\n
                <br> <a href="{reset_url}"><button style="background-color:blue; color:white; border:1px solid blue; font-weight:bold;">
                Reset Password</button></a>""",
                from_email = settings.DEFAULT_FROM_EMAIL,
                recipient_list=[email],
                fail_silently=False,
            )
            messages.success(request, "Paasword reset instructions have been sent to your email.")
        except UserRegistration.DoesNotExist:
            messages.error(request, "Email not found. Please enter a registered email.")
    return render(request,'forgot.html')

# Reset Views
def reset(request, user_id):
    try:
        user = UserRegistration.objects.get(pk=user_id)
    except UserRegistration.DoesNotExist:
            messages.error(request, "Invalid password reset link.")
            return redirect("forgot")
    
    if request.method == "POST":
        new_password = request.POST.get("get_password")
        confirm_password = request.POST.get("confirm_password")

        if new_password != confirm_password:
            messages.error(request, "Passwords do not match.")
        else:
            user.password = make_password(new_password)

            user.save()
            messages.success(request, "Your password has been reset sucessfully.")
            return redirect("log")
        
    return render(request,'reset.html', {"user_id": user_id})

# Register views
def reg(request):
    if request.method == "POST":
        username = request.POST.get("username")
        email = request.POST.get("email")
        password = request.POST.get("password")
        confirmpass = request.POST.get("Confirmpassword")

        # Check if passwords match
        if password != confirmpass:
            messages.error(request,"Passwords do not match!")
            return redirect("reg") 
        
        # Check if user already exists
        if UserRegistration.objects.filter(email=email).exists():
            messages.error(request,"Email already registered!")
            return redirect("reg")

        # # Check if username already exists
        # if UserRegistration.objects.filter(username=username).exists():
        #     messages.error(request,"Username already registered!")
        #     return redirect("reg")    
        
        # Save new user
        hash_password = make_password(password)
        user = UserRegistration(username=username,email=email,password=hash_password)
        user.save()

        messages.success(request,"Registration sucessfull! Please login.")
        return redirect("log")
    
    return render(request,'register.html')

#Logout views
def logout_view(request):
    request.session.clear()  # Clear all session data
    logout(request)  # Log out the user
    messages.success(request,"Logged out sucessfully")
    return redirect('log')

@login_required
# Base views
def base(request):
    user_id = request.session.get('userid')
    username = UserRegistration.objects.get(id=user_id)

    context={
        'user':username,
    }
    return render(request,'base.html',context)


@csrf_protect
@login_required
def mark_all_as_read(request):
    # print("Request method:", request.method)
    
    if request.method == "GET":
        # print("Request method:", request.method)

        # print("POST received")
        user =request.session.get('userid')
        unread_notifications = Notification.objects.filter(user=user, is_read=False)
        
        if unread_notifications.exists():
            unread_notifications.update(is_read=True)
            unread_count = Notification.objects.filter(user=user, is_read=False).count()
            return JsonResponse({"success": True, "unread_count": unread_count})
        else:
            return JsonResponse({"success": True, "unread_count": 0})

    # print("Not a POST request")
    return JsonResponse({"success": False}, status=400)

# Dashboard views
# @login_required
def dash(request):
    user_id = request.session.get('userid')
    username = UserRegistration.objects.get(id=user_id)
    notifications = Notification.objects.filter(user=username).order_by('-timestamp')

    steganography_count = EncodedImage.objects.filter(original_image__user_id=user_id).count()
    cryptography_count = EncryptedMessage.objects.filter(userid=user_id).count()

   # Only count images that have a watermarked image but have NOT been steganographed
    watermarking_count = UploadedImage.objects.filter(
        user_id=user_id,
        watermarked_image__isnull=False,
        encodedimage__isnull=True  # Ensure it's not used in steganography
    ).count()

    tampering_count = TamperingDetection.objects.filter(models.Q(uploaded_image__user_id=user_id) | models.Q(encoded_image__original_image__user_id=user_id)).count()

    # Calculate total operations
    total_operations = steganography_count + cryptography_count + watermarking_count + tampering_count

    # Avoid division by zero
    progress_data = {
        'Steganography': (steganography_count / total_operations * 100) if steganography_count else 0,
        'Cryptography': (cryptography_count / total_operations * 100) if cryptography_count else 0,
        'Watermarking': (watermarking_count / total_operations * 100) if watermarking_count else 0,
        'Tampering': (tampering_count / total_operations * 100) if tampering_count else 0,
    } if total_operations else {'Steganography': 0, 'Cryptography': 0, 'Watermarking': 0, 'Tampering': 0}


    recent_logins = UserloginHistory.objects.filter(user=username).order_by("-login_time")
    logs = UserActivityLog.objects.filter(user=user_id).order_by("-timestamp")

    # Categorise logs
    today = date.today()
    start_of_week = today - timedelta(days=today.weekday())

    # Get Todays logs
    today_logs = logs.annotate(date_only=TruncDate('timestamp')).filter(date_only=today)

    # Get this week's logs (excluding today's logs)
    this_week_logs = logs.filter(timestamp__gte = start_of_week).exclude(id__in=today_logs.values_list('id', flat=True))

    # Get all previous logs (excluding this week)
    all_logs = logs.filter(timestamp__lt = start_of_week)
    
    recent_activities = logs
    context={
        'user':username,
        "steganography_count": steganography_count,
        "cryptography_count": cryptography_count,
        "watermarking_count": watermarking_count,
        "tampering_count": tampering_count,
        "total_operations" : total_operations,
        "progress_data" : progress_data,
        "recent_logins" : recent_logins,
        "recent_activities" : recent_activities,
        'today_logs': today_logs,
        'this_week_logs': this_week_logs,
        'all_logs': all_logs,
        'user_id':user_id,
        'notifications':notifications
    }
    return render(request,'dashboard.html',context)

# Profile Page View
@login_required
def profile(request):
    user_id = request.session.get('userid') 
    user = UserRegistration.objects.get(id=user_id)
     # Fetch user manually
    notifications = Notification.objects.filter(user=user.id).order_by('-timestamp')

    if request.method == "POST":
        bio = request.POST.get('bio', '').strip()
        purpose = request.POST.get('purpose', '').strip()

        if purpose:
            user.purpose = purpose  # Update purpose if provided
        if bio:
            user.bio = bio  # Update bio if provided

        user.save()

        # Log the activity
        UserActivityLog.objects.create(user=user, action="Updated user information")

        messages.success(request, "Profile updated successfully.")

    
    return render(request, 'profile.html', {
        'user': user,
        'user_id':user_id,
        'notifications' : notifications,
        })

# Update Username View
@login_required
def update_username(request):
    if request.method == "POST":
        user = UserRegistration.objects.get(id=request.session.get('userid'))
        current_password = request.POST.get("current_password")
        new_username = request.POST.get("new_username")

        if not check_password(current_password, user.password):
            messages.error(request, "Incorrect password.")
            return redirect("profile")

        user.username = new_username
        user.save()

        # Log the activity
        UserActivityLog.objects.create(user=user, action="Updated user information")

        messages.success(request, "Username updated successfully.")
        return redirect("profile")

    messages.error(request, "Invalid request method.")

    # Store message in the notifications database
    for message in messages.get_messages(request):
        Notification.objects.create(user=user, message=message)

    return redirect("profile")

# Update Email View
@login_required
def update_email(request):
    if request.method == 'POST':
        user = UserRegistration.objects.get(id=request.session.get('userid'))
        new_email = request.POST.get('new_email')
        current_password = request.POST.get('current_password')

        if not check_password(current_password, user.password):
            messages.error(request, 'Incorrect password.')
            return redirect('profile')

        user.email = new_email
        user.save()

        # Log the activity
        UserActivityLog.objects.create(user=user, action="Updated user information")
        
        messages.success(request, 'Email updated successfully.')
    return redirect('profile')

# Update Password View
@login_required
def update_password(request):
    if request.method == 'POST':
        user = UserRegistration.objects.get(id=request.session.get('userid'))
        old_password = request.POST.get('old_password')
        new_password = request.POST.get('new_password')
        confirm_password = request.POST.get('confirm_password')

        if not check_password(old_password, user.password):
            messages.error(request, 'Incorrect current password.')
        elif new_password != confirm_password:
            messages.error(request, 'New passwords do not match.')
        else:
            user.password = make_password(new_password)
            user.save()
            update_session_auth_hash(request, user)  # Keep user logged in after password change
            
            # Log the activity
            UserActivityLog.objects.create(user=user, action="Updated user information")

            messages.success(request, 'Password updated successfully.')

    return redirect('profile')

# Update Profile Picture View
@login_required
def update_profile_picture(request):
    user_id = request.session.get('userid')  
    if request.method == "POST" and request.FILES.get("profile_picture"):
        try:
            user = UserRegistration.objects.get(id=user_id)  # Fetch the user profile
            user.profile_picture = request.FILES["profile_picture"]
            user.save()
            # Log the activity
            UserActivityLog.objects.create(user=user, action="Updated user information")

            messages.success(request, "Profile picture updated successfully!")
        except UserRegistration.DoesNotExist:
            messages.error(request, "User profile not found.")
        except Exception as e:
            messages.error(request, f"An error occurred: {e}")

    return redirect("profile") 
@login_required
def profilecheck_password(request):
    if request.method == "POST":
        password = request.POST.get("password")
        user_id = request.session.get('userid')
        try:
            registered_user = UserRegistration.objects.get(id=user_id)
            psw=registered_user.password
            if check_password(password, registered_user.password):
                return JsonResponse({"valid": True})  # Password correct
            else:
                
                return JsonResponse({"valid": False})  # Password incorrect
        except UserRegistration.DoesNotExist:
            return JsonResponse({"valid": False})  # User not found

    return JsonResponse({"valid": False})  # Invalid request

@login_required
def delete_account(request):
    if request.method == "POST":
        password = request.POST.get("password")
        user_id = request.session.get('userid')
        try:
            registered_user = UserRegistration.objects.get(id=user_id)
            if check_password(password, registered_user.password):
                registered_user.delete()  # Delete user from the database
                logout(request)  # Log out the user
                return JsonResponse({"deleted": True})  # Confirm deletion
            else:
                return JsonResponse({"deleted": False})  # Password incorrect
        except UserRegistration.DoesNotExist:
            return JsonResponse({"deleted": False})  # User not found

    return JsonResponse({"deleted": False}) 

# Watermark adding views
def add_watermark(image_path, watermark_path=None, watermark_text=None, position="bottom-right"):
    """Applies either an image watermark or text watermark at a user-specified position"""
    img = cv2.imread(image_path)

    if img is None:
        print("Error: Image could not be loaded")
        return None
    
    h_img, w_img, _ = img.shape # Get dimensions of the main image

    if watermark_path:
        # Apply image watermark
        logo = cv2.imread(watermark_path, cv2.IMREAD_UNCHANGED)
        if logo is None:
            print("Error: Logo could not be loaded")
            return None
        
        """Convert logo to BGR If it has an alpha channel (transperancy)"""
        if logo.shape[-1] == 4: # If the watermark has 4 channels
            logo = cv2.cvtColor(logo, cv2.COLOR_BGRA2BGR) # Convert to BGR
    
        h_logo,w_logo, _ = logo.shape # Get dimensions of the main image

        """Resize logo dynamically to fit within 20% of the image width"""
        new_width = int(w_img * 0.1) # Set logo width to 20% of the image width
        aspect_ratio = h_logo / w_logo
        new_height = int(new_width * aspect_ratio)

        logo = cv2.resize(logo, (new_width, new_height), interpolation=cv2.INTER_AREA)

        """Get new logo dimensions after resizing"""
        h_logo, w_logo = logo.shape[:2]  # Get only height & width

        """Determine placement coordinates"""
        positions = {
            "top-left": (10,10),
            "top-right": (w_img - w_logo - 10, 10),
            "bottom-left": (10, h_img - h_logo - 10),
            "bottom-right": (w_img - w_logo -10, h_img - h_logo - 10)
        }

        # Get the selected position coordinates
        left_x, top_y = positions.get(position, positions["bottom-right"])
        bottom_y, right_x = top_y + h_logo, left_x + w_logo
        
        """Blend the watermark with image"""
        destination = img[top_y:bottom_y, left_x:right_x].astype(np.float32)

        """Convert both to float32 for blending"""
        logo = logo.astype(np.float32)

        """Perform weighted addition (blend images)"""
        result = cv2.addWeighted(destination, 1, logo, 0.5, 0)

        """Replace the region in the original image with the blended result"""
        img[top_y:bottom_y, left_x:right_x] = result.astype(np.uint8)

    elif watermark_text:
        # Apply text watermark
        font = cv2.FONT_HERSHEY_SIMPLEX  # OpenCV built-in font commonly used for displaying text on images
        font_scale = min(w_img, h_img)/ 800 # Adjust font size based on image size
        font_thickness = int(font_scale * 2)

        text_color = (255, 255, 255) # White color
        

        (text_width, text_height), _ = cv2.getTextSize(watermark_text, font, font_scale, font_thickness)

        """Determine text placement"""
        positions = {
            "top-left": (20, text_height +20),
            "top-right": (w_img - text_width - 20, text_height + 20),
            "bottom-left": (20, h_img - 20),
            "bottom-right": (w_img - text_width - 20, h_img - 20)
        }
        text_x, text_y = positions.get(position, positions['bottom-right'])

        """Create an overlay for blending"""
        overlay = img.copy()
        
        """Apply text on overlay"""
        cv2.putText(overlay, watermark_text, (text_x, text_y),
                    font, font_scale, text_color, font_thickness, cv2.LINE_AA)
        
        """Blend the overlay with the original image to add opacity"""
        img = cv2.addWeighted(overlay, 0.5, img, 0.5, 0)

    """Convert OpenCV Image to Django File """
    _, buffer = cv2.imencode('.jpg', img)
    return ContentFile(buffer.tobytes(), name="watermarked_{{id}}.jpg")

#Watermarking views
@login_required
def Watermark(request):
    user_id = request.session.get('userid')
    username = UserRegistration.objects.get(id=user_id)
    notifications = Notification.objects.filter(user=username).order_by('-timestamp')

    """Handles image logo uploads for watermarking with either an image or text."""
    show_download = False # Default: Hide download button
    preview_url = None # Default: No preview image

    if request.method == 'POST' and 'image' in request.FILES:
        uploaded_image_file = request.FILES['image']

        # Calculate the SHA-256 hash of the original image
        image_hash = calculate_image_hash(uploaded_image_file)

        uploaded_Image = UploadedImage(
            original_image=uploaded_image_file,
            original_hash = image_hash,
            user_id=user_id
        )

        watermark_text = request.POST.get('watermark_text', None)
        watermark_position = request.POST.get('watermark_position')

        # Check if a logo is uploaded
        if 'logo' in request.FILES:
            uploaded_Image.watermark_logo = request.FILES['logo']

        uploaded_Image.watermark_position = watermark_position  # Assign user value
        uploaded_Image.save()
        
        # Generate an encrypt an AES key for watermarking
        encrypted_aes_key, _, iv, _ = encrypt_message("dummy") # AES key generated inside

        # Ensure IV is stored correctly
        if not iv or len(iv) < 8:
            iv = os.urandom(12)  # Regenerate IV with correct size

        # Ensure IV is stored as bytes (fixes memoryview issue)
        if isinstance(iv, memoryview):
            iv = bytes(iv)
        
        """Apply watermark based on user input (image or text)"""
        if uploaded_Image.watermark_logo:
            watermarked_file = add_watermark(
                uploaded_Image.original_image.path,
                uploaded_Image.watermark_logo.path,
                position = watermark_position
                )
        
        elif watermark_text:
            watermarked_file = add_watermark(
                uploaded_Image.original_image.path,
                watermark_text=watermark_text,
                position=watermark_position
                )
        
        else:
            messages.error(request, "Please provide a watermark (text or logo).")
            return redirect("Watermark")

        if watermarked_file:
            uploaded_Image.watermarked_image.save(watermarked_file.name, watermarked_file)
            uploaded_Image.save()

            # Calculate hash of the watermarked image.
            with open(uploaded_Image.watermarked_image.path, 'rb') as wf:
                watermarked_image_hash = hashlib.sha256(wf.read()).hexdigest()

            # Store the hash value and the encrypted key in the database
            WatermarkKey.objects.create(
                image = uploaded_Image,
                watermarked_hash = watermarked_image_hash,
                encrypted_aes_key = encrypted_aes_key,
                iv = iv,
            )
            
            # Log the steganography activity
            UserActivityLog.objects.create(user=username, action="Performed Forensic Watermarking")

            # Store notification in the database
            Notification.objects.create(
                user=username,  
                message="Watermark successfully applied to the Image."
            )

            # Add success message
            messages.success(request, 'The watermark has been successfully applied to the image.')
            show_download = True # Show the button
            preview_url = uploaded_Image.watermarked_image.url  # Image preview

            # Redirect with preview URL
            return redirect(f"{reverse('Watermark')}?preview_url=/media/{uploaded_Image.watermarked_image.name}")

        else:
            # Add error message if watermarking fails
            messages.error(request, 'Failed to apply the watermark. Please try again.')

    
    images = UploadedImage.objects.all()    
    preview_url = request.GET.get('preview_url', None)
    show_download = bool(preview_url)    
    return render(request,'Watermark.html', {
        'images':images,
        'show_download': show_download,
        'preview_url': preview_url,
        'user':username,
        'notifications':notifications,  
        })


@login_required
def download_watermarked_image(request, image_id):
    try:
        image = UploadedImage.objects.get(id=image_id, user_id=request.session.get('userid'))
        file_path = image.watermarked_image.path

        if os.path.exists(file_path):
            response = FileResponse(open(file_path, 'rb'), content_type='image/png')
            response['Content-Disposition'] = f'attachment; filename="{os.path.basename(file_path)}"'
            return response
        else:
            raise Http404("Watermarked image not found.")
    except UploadedImage.DoesNotExist:
        raise Http404("Image not found.")

#Encryption views
@login_required
def Encrypt(request):
    user_id = request.session.get('userid')
    username = UserRegistration.objects.get(id=user_id)
    notifications = Notification.objects.filter(user=username).order_by('-timestamp')

    if request.method == "POST":
        title = request.POST.get("title","Untitled")
        message = request.POST.get("message")

        try:

            enc_key, enc_msg, nonce, tag = encrypt_message(message)
            # Encrypting data based on user
            usid=request.session['userid']
            encrypted_instance = EncryptedMessage(
                title=title,
                encrypted_aes_key = enc_key,
                cipher_text = enc_msg,
                nonce = nonce,
                tag = tag,
                userid_id=usid
            )
            encrypted_instance.save()

            # Log the steganography activity
            UserActivityLog.objects.create(user=username, action="Performed Encryption")

            # Store notification in the database
            Notification.objects.create(
                user=username,  
                message="Text encryption successfull"
            )
            
            messages.success(request, "Encryption successful! Your ciphertext is generated.")
            
            return render(request, "Encrypt.html",{
                "success": True,
                "ciphertext": enc_msg.hex(),
                "enc_id" : encrypted_instance.id,
            })
        except Exception as e:
            return render(request,"Encrypt.html",{"error":f"Encryption failed: {str(e)}"})

    return render(request,'Encrypt.html',{'notifications' : notifications,'user':username })

def DownloadCiphertext(request, enc_id):
    """ Generates a downloadable text file containing the ciphertext. """
    encrypted_instance = get_object_or_404(EncryptedMessage, id=enc_id)
    
    
    # Prepare the ciphertext as a hex string for better readability
    ciphertext_hex = encrypted_instance.cipher_text.hex()

    response = HttpResponse(ciphertext_hex, content_type="text/plain")
    response['Content-Disposition'] = f'attachment; fiename="ciphertext_{enc_id}.txt"'

    return response

# Decryption views
@login_required
def Decrypt(request):
    user_id = request.session.get('userid')
    username = UserRegistration.objects.get(id=user_id)
    loggeduserid=request.session.get('userid')
    # Displaying data based on the user_id
    encrypted_messages = EncryptedMessage.objects.filter(userid=loggeduserid).order_by("-created_at")
    notifications = Notification.objects.filter(user=username).order_by('-timestamp')

    decrypted_text = None
    error_messages = None

    if request.method == "POST":
        enc_id = request.POST.get("enc_id")
        ciphertext_input = request.POST.get("cipher_text").strip()  # Get user input

        try:
            if enc_id:   # If the user provided an ID, fetch stored ciphertext
                encrypted_instance = get_object_or_404(EncryptedMessage, id=enc_id)
                encrypted_aes_key = bytes(encrypted_instance.encrypted_aes_key)
                cipher_text = bytes(encrypted_instance.cipher_text) 
                nonce = bytes(encrypted_instance.nonce)
                tag = bytes(encrypted_instance.tag)
            
            elif ciphertext_input:  # If user pasted ciphertext manually
                #  Convert the input (hex string) to bytes
                ciphertext_bytes = bytes.fromhex(ciphertext_input)
                # Retrieve the corresponding encryption details from the database
                encrypted_instance = EncryptedMessage.objects.filter(cipher_text=ciphertext_bytes).first()
                if not encrypted_messages:
                    raise ValueError("Ciphertext not found in the database.")

                # Convert memoryview objects to bytes before decryption
                encrypted_aes_key = bytes(encrypted_instance.encrypted_aes_key)
                cipher_text = bytes(encrypted_instance.cipher_text)  # FIX: Directly convert from memoryview
                nonce = bytes(encrypted_instance.nonce)
                tag = bytes(encrypted_instance.tag)

            else:
                raise ValueError("Please provide either an ID or paste the ciphertext.")

            # Decrypt the message
            decrypted_text = decrypt_message(encrypted_aes_key, cipher_text, nonce, tag)

            # Log the steganography activity
            UserActivityLog.objects.create(user=username, action="Performed Decryption")

            # Store notification in the database
            Notification.objects.create(
                user=username,  
                message="Cipher-Text Decryption Successfull."
            )

            messages.success(request, "Decryption successful! Your data is extracted.")

        except EncryptedMessage.DoesNotExist:
            decrypted_text = "Error: No matching encrypted message found."
        except Exception as e:
            decrypted_text = f"Decryption failed: {str(e)}"
            print("ERROR:", decrypted_text)  # Debugging output

    return render(request, "Decrypt.html", {
        "decrypted_text": decrypted_text,
        "error_message": error_messages,
        "encrypted_messages": encrypted_messages,
        'user':username,
        'notifications' : notifications,
        })


# Image Steganography views
@login_required
def steg(request):
    user_id = request.session.get('userid')
    username = UserRegistration.objects.get(id=user_id)
    notifications = Notification.objects.filter(user=username).order_by('-timestamp')

    if request.method == 'POST':
        image = request.FILES.get('image')
        secret_message = request.POST.get('secret_message')
        
        if not image or not secret_message:
            return JsonResponse({'error': 'Missing image or secret message'}, status=400)

        # Save the uploaded image
        uploaded_image = UploadedImage(
            original_image=image,
            user_id=user_id
            )
        
        uploaded_image.save()

        input_path = uploaded_image.original_image.path
        image_hash = calculate_image_hash(image)

        # Check if the hash exists in the watermarked images.
        if not WatermarkKey.objects.filter(watermarked_hash=image_hash).exists():
            messages.error(request, "Only watermarked images are allowed for Image Steganography.")
        
        uploaded_image.original_hash = image_hash
        uploaded_image.save()

        output_filename = f'encoded_{uploaded_image.id}.png'
        output_path = os.path.join('media/encoded_images', output_filename)

        try:
            encode_image(input_path, secret_message, output_path)

            with open(output_path, 'rb') as ef:
                encoded_image_hash = hashlib.sha256(ef.read()).hexdigest()

            encoded_image_instance = EncodedImage(
                original_image=uploaded_image,
                encoded_image=f'encoded_images/{output_filename}',
                secret_data=secret_message,
                encoded_hash = encoded_image_hash
            )
            encoded_image_instance.save()

            # Log the steganography activity
            UserActivityLog.objects.create(user=username, action="Performed Image Steganography")
            
            # Store notification in the database
            Notification.objects.create(
                user=username,  
                message="Message successfully encoded into the image."
            )

            # Add success message
            messages.success(request, 'The message has been successfully encoded into the image.')
            
            return render(request, 'Steg.html', {'download_url': encoded_image_instance.encoded_image.url})

        except ValueError as e:
            return JsonResponse({'error': str(e)}, status=400)

    return render(request, 'Steg.html',{'notifications' : notifications, 'user':username})

@login_required
def steganalysis(request):
    user_id = request.session.get('userid')
    username = UserRegistration.objects.get(id=user_id)
    notifications = Notification.objects.filter(user=username).order_by('-timestamp')
    decoded_message = None  # Initialize the variable for the decoded message
    uploaded_image_url = None  # Initialize the variable for the uploaded image URL

    if request.method == 'POST':
        image = request.FILES.get('image')

        if not image:
            return JsonResponse({'error': 'Missing image'}, status=400)

        # Save the uploaded image to the 'images/' folder as per the model definition
        uploaded_image = UploadedImage(original_image=image)
        uploaded_image.save()

        input_path = uploaded_image.original_image.path
        # The URL of the uploaded image, which will be relative to the media URL
        uploaded_image_url = uploaded_image.original_image.url  

        try:
            decoded_message = decode_image(input_path)

            # Log the steganography activity
            UserActivityLog.objects.create(user=username, action="Performed Image Steganalysis")
            
            # Store notification in the database
            Notification.objects.create(
                user=username,  
                message="Message successfully decoded from the image."
            )

            # Add success message
            messages.success(request, 'The message has been successfully decoded from the image.')

        except ValueError as e:
            return JsonResponse({'error': str(e)}, status=400)

    return render(request, 'Steganalysis.html', {
        'decoded_message': decoded_message, 'uploaded_image_url': uploaded_image_url,
        'user':username, 'notifications' : notifications })

# Tampering Views
@login_required
def Tamper(request):
    user_id = request.session.get('userid')
    username = UserRegistration.objects.get(id=user_id)
    notifications = Notification.objects.filter(user=username).order_by('-timestamp')

    status = "Pending Analysis"  # Default status for GET requests
    image_hash = "N/A"   # Ensure image_hash is always defined
    matched_instance = None
    original_hash = "N/A"
    uploaded_image_url = None
    new_entry = None
    logs = []  # Initialize logs as an empty list to prevent 'referenced before assignment' error

    if request.method == 'POST' and request.FILES.get('image'):
        uploaded_image = request.FILES['image']
        image_hash = calculate_image_hash(uploaded_image)

        # print("Uploaded Image Hash:", image_hash)  # Debugging: See if hash changes

        # Check if the hash exists in the stored images
        matched_original = UploadedImage.objects.filter(original_hash=image_hash).first()
        matched_watermarked = UploadedImage.objects.filter(id__in=WatermarkKey.objects.filter(watermarked_hash=image_hash).values('image_id')).first()
        matched_steganographed = EncodedImage.objects.filter(encoded_hash=image_hash).first()

        if matched_original:
            status = "Original Image"
            matched_instance = matched_original
            uploaded_image_url = matched_original.original_image.url
            original_hash = matched_original.original_hash

            # Store notification in the database
            Notification.objects.create(
                user=username,  
                message="Image Verified Successfully"
            )
            messages.success(request, "No Tampering Detected! The image matches the original.")

        elif matched_watermarked:
            status = "Watermarked Image"
            matched_instance = matched_watermarked
            uploaded_image_url = matched_watermarked.watermarked_image.url
            original_hash = WatermarkKey.objects.filter(image_id=matched_watermarked.id).first().watermarked_hash
            
            # Store notification in the database
            Notification.objects.create(
                user=username,  
                message="Watermarked Image Verified Successfully"
            )
            messages.success(request, "No Tampering Detected! The image matches the Watermarked version.")

        elif matched_steganographed:
            status = "Steganographed Image"
            matched_instance = matched_steganographed
            uploaded_image_url = matched_steganographed.encoded_image.url
            original_hash = matched_steganographed.encoded_hash
            
            # Store notification in the database
            Notification.objects.create(
                user=username,  
                message="Steganographed Image Verified Successfully"
            )
            messages.success(request, "No Tampering Detected! The image matches the Steganographed version.")

        else:
            status = "Image Tampered"
            
            # Store notification in the database
            Notification.objects.create(
                user=username,  
                message="Warning: Tampering Detected!"
            )
            messages.error(request, "Warning: Tampering Detected! The uploaded image does not match originally stored hash.")

    try:
        if isinstance(matched_instance, str):
            filename = os.path.basename(matched_instance)
            # Try retrieving from UploadedImage (Watermarked)
            matched_instance = UploadedImage.objects.filter(watermarked_image__contains=filename).first()

            # If not found in UploadedImage, check in EncodedImage (Steganographed)
            if not matched_instance:
                matched_instance = EncodedImage.objects.filter(encoded_image__contains=filename).first()

        if matched_instance:
            try:
                TamperingDetection.objects.create(
                    uploaded_image=matched_instance if isinstance(matched_instance, UploadedImage) else None,
                    encoded_image=matched_instance if isinstance(matched_instance, EncodedImage) else None,
                    tampering_check_hash=image_hash,
                    detected_at=now(),
                    status=status,
                )

                # Log the steganography activity
                UserActivityLog.objects.create(user=username, action="Performed Tampering Detection")

            except Exception as e:
                print(f"ERROR Creating TamperingDetection Entry: {e}")

        # Fetch the latest tampering logs
        logs = TamperingDetection.objects.order_by('-id')[:5]

    except Exception as e:
        print(f"ERROR: {e}")

    context = {
        'user': username,
        'status': status,
        'original_hash': original_hash,
        'current_hash': image_hash,
        'uploaded_image_url': uploaded_image_url,
        'logs': logs,
        'notifications' : notifications,
    }
    return render(request, 'Tampering.html', context)


# Guide views

def Guide(request):
    user_id = request.session.get('userid')
    username = UserRegistration.objects.get(id=user_id)
    notifications = Notification.objects.filter(user=username).order_by('-timestamp')

    context={
        'user':username,
        'notifications' : notifications,
    }
    return render(request,'guide.html',context)

# Contact Views
def Support(request):
    if request.method == "POST":
        subject = request.POST.get("subject")
        message = request.POST.get("message")

        if request.session.get('userid'):
            user = UserRegistration.objects.get(id=request.session['userid'])
            name = user.username
            email = user.email
            user_info = f"User ID: {user.id}\n Name: {name} \n Email: {email}"


        if name and email and subject and message:
            # Send Email
            send_mail(
                subject=f"{subject}",
                message = f"{user_info}\n\n Message: {message}",
                from_email=email,
                recipient_list=["jayuj6028@gmail.com"],
                fail_silently= False,
            )
            
            # Log the steganography activity
            UserActivityLog.objects.create(user=user, action="Contacted Support")

            messages.success(request, "Your message has been sent successfully!")
            return redirect("Support")
        else:
            messages.error(request,"All fields are required")

    return render(request, 'guide.html')
