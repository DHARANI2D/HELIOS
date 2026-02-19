from PIL import Image, ImageDraw, ImageFont
import os

def generate_test_image(text, output_path):
    # Create a white image
    img = Image.new('RGB', (400, 200), color=(255, 255, 255))
    d = ImageDraw.Draw(img)
    
    # Try to load a font, otherwise use default
    try:
        font = ImageFont.truetype("Arial.ttf", 20)
    except Exception:
        font = ImageFont.load_default()
    
    # Draw the text
    d.text((50, 80), text, fill=(0, 0, 0), font=font)
    
    # Save the image
    img.save(output_path)
    print(f"Test image saved to {output_path}")

if __name__ == "__main__":
    generate_test_image("Click here: http://net20.cc", "ocr_test1.png")
