import numpy as np
import cv2
import pytesseract

def decode_watermark(image_path, watermark_position, watermark_type="image"):
    try:
        image = cv2.imread(image_path, cv2.IMREAD_UNCHANGED)
        
        if image is None:
            print("❌ Error: Unable to load image for watermark extraction.")
            return None
        
        print(f"✅ Image Loaded for Decoding. Shape: {image.shape}, Type: {type(image)}")
        print(f"🔎 Decoding watermark from position: {watermark_position}")

        h_img, w_img, _ = image.shape  # Get image dimensions
        watermark_size = int(w_img * 0.2)  # Estimate watermark size (20% of width)

        positions = {
            "top-left": (10, 10, 10 + watermark_size, 10 + watermark_size),
            "top-right": (w_img - watermark_size - 10, 10, w_img - 10, 10 + watermark_size),
            "bottom-left": (10, h_img - watermark_size - 10, 10 + watermark_size, h_img - 10),
            "bottom-right": (w_img - watermark_size - 10, h_img - watermark_size - 10, w_img - 10, h_img - 10)
        }

        if watermark_position not in positions:
            print(f"❌ Error: Invalid watermark position '{watermark_position}' provided.")
            return None
        
        x1, y1, x2, y2 = positions[watermark_position]

        if watermark_type == "text":
            gray = cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)
            roi = gray[y1:y2, x1:x2]
            _, binary = cv2.threshold(roi, 150, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
            resized = cv2.resize(binary, (binary.shape[1] * 2, binary.shape[0] * 2), interpolation=cv2.INTER_LINEAR)
            extracted_text = pytesseract.image_to_string(resized, lang='eng', config="--psm 7").strip()
            
            if not extracted_text:
                print("❌ Error: No text watermark detected.")
                return None
            
            return extracted_text

        elif watermark_type == "image":
            roi = image[y1:y2, x1:x2].copy()
            gray_roi = cv2.cvtColor(roi, cv2.COLOR_BGR2GRAY)
            _, mask = cv2.threshold(gray_roi, 180, 255, cv2.THRESH_BINARY)
            mask = cv2.bitwise_not(mask)
            extracted_watermark = cv2.bitwise_or(roi, roi, mask=mask)
            extracted_watermark = cv2.cvtColor(extracted_watermark, cv2.COLOR_BGR2RGB)
            extracted_watermark = np.array(extracted_watermark, dtype=np.uint8)
            
            print(f"✅ Extracted Watermark Shape: {extracted_watermark.shape}, Type: {type(extracted_watermark)}")
            print(f"🖼️ Extracted position: {watermark_position}")
            return extracted_watermark

        else:
            print("❌ Error: Invalid watermark type. Choose 'text' or 'image'.")
            return None

    except Exception as e:
        print(f"❌ Exception in decode_watermark: {e}")
        return None
