import re
import urllib.parse
import html
import os
import logging
import io
from oletools.olevba import VBA_Parser
from oletools.oleobj import find_ole
from pdfminer.high_level import extract_text
from PIL import Image
try:
    import pytesseract
except ImportError:
    pytesseract = None

logger = logging.getLogger("uvicorn")

def is_tesseract_available() -> bool:
    if not pytesseract: return False
    try:
        pytesseract.get_tesseract_version()
        return True
    except Exception:
        return False

# -------- CONFIG derived from User Request --------
URL_REGEX = r'https?://[^\s"<>()]+'

NOISE_DOMAINS = (
    "w3.org",
    "googleapis.com",
    "gstatic.com",
    "fonts.googleapis.com",
    "schemas.microsoft.com",
)

TEXT_EXTENSIONS = (
    ".txt", ".html", ".htm", ".eml", ".csv", ".xml", ".json"
)

def decode_urldefense(url: str) -> str:
    """
    Decodes Proofpoint Urldefense (v1, v2, v3) and Microsoft Safelinks URLs.
    Returns original URL if not a wrapper or if decoding fails.
    """
    try:
        # Proofpoint v3: https://urldefense.com/v3/__TARGET__;!!...
        if "/v3/" in url and "urldefense" in url:
            match = re.search(r'/v3/__(.+?)__;!!', url)
            if match:
                return urllib.parse.unquote(match.group(1))
        
        # Proofpoint v2: https://urldefense.com/v2/url?u=TARGET&...
        elif "/v2/" in url and "urldefense" in url:
            parsed = urllib.parse.urlparse(url)
            qs = urllib.parse.parse_qs(parsed.query)
            encoded = qs.get('u', [''])[0]
            if encoded:
                trans = str.maketrans('-_', '%/')
                return urllib.parse.unquote(encoded.translate(trans))

        # Proofpoint v1: https://urldefense.com/v1/url?u=TARGET&k=...
        elif "/v1/" in url and "urldefense" in url:
            parsed = urllib.parse.urlparse(url)
            qs = urllib.parse.parse_qs(parsed.query)
            return qs.get('u', [url])[0]

        # Microsoft Safelinks: https://*.safelinks.protection.outlook.com/?url=TARGET&...
        elif "safelinks.protection.outlook.com" in url:
            parsed = urllib.parse.urlparse(url)
            qs = urllib.parse.parse_qs(parsed.query)
            return qs.get('url', [url])[0]

    except Exception:
        pass

    return url

def is_noise(url: str) -> bool:
    return any(n in url.lower() for n in NOISE_DOMAINS)

def process_raw_urls(raw_urls: set) -> list[str]:
    """
    Applies decoding and noise filtering to a set of raw URLs.
    """
    clean_urls = set()

    for url in raw_urls:
        # DROP ALL urldefense URLs / Decode them
        if "urldefense.com" in url or "safelinks.protection" in url:
            decoded = decode_urldefense(url)
            if decoded and not is_noise(decoded):
                clean_urls.add(decoded)
            continue

        # Keep normal URLs only
        if not is_noise(url):
            clean_urls.add(url)
            
    return sorted(list(clean_urls))

def extract_urls_from_text(text: str) -> list[str]:
    """
    Extracts URLs from a string using the specified regex.
    """
    if not text: return []
    # Unescape HTML entities before matching to clean up &amp; etc.
    decoded_text = html.unescape(text)
    raw_urls = set(re.findall(URL_REGEX, decoded_text))
    return process_raw_urls(raw_urls)

def extract_urls_from_files(files: list[str]) -> list[str]:
    """
    Extracts URLs from a list of file paths.
    """
    raw_urls = set()
    for file in files:
        if not os.path.exists(file): continue
        try:
            # Determine logic based on extension
            low = file.lower()
            if low.endswith(TEXT_EXTENSIONS):
                with open(file, "r", errors="ignore") as f:
                    content = html.unescape(f.read())
                    raw_urls.update(re.findall(URL_REGEX, content))
            elif low.endswith((".xls", ".xlsx", ".xlsm")):
                raw_urls.update(analyze_excel(file))
            elif low.endswith(".pdf"):
                raw_urls.update(analyze_pdf(file))
            elif low.endswith((".png", ".jpg", ".jpeg", ".bmp", ".tiff")):
                raw_urls.update(analyze_image(file))
        except Exception as e:
            logger.error(f"Error extracting URLs from {file}: {e}")
            
    return process_raw_urls(raw_urls)

def extract_urls_recursive(root_dir: str) -> list[str]:
    """
    Recursively extract URLs from ALL readable files inside a directory.
    """
    all_files = []
    for root, _, files in os.walk(root_dir):
        for file in files:
            all_files.append(os.path.join(root, file))
    
    return extract_urls_from_files(all_files)

def analyze_excel(path: str) -> set:
    urls = set()
    # ---- VBA MACROS ----
    try:
        vbaparser = VBA_Parser(path)
        if vbaparser.detect_vba_macros():
            for (_, _, _, code) in vbaparser.extract_macros():
                urls.update(re.findall(URL_REGEX, code))
        vbaparser.close()
    except Exception:
        pass

    # ---- EMBEDDED OLE OBJECTS ----
    try:
        for ole in find_ole(path):
            if ole.data:
                try:
                    text = ole.data.decode(errors="ignore")
                    urls.update(re.findall(URL_REGEX, text))
                except Exception:
                    pass
    except Exception:
        pass
    return urls

def analyze_pdf(path: str) -> set:
    urls = set()
    try:
        text = extract_text(path)
        urls.update(re.findall(URL_REGEX, text))
    except Exception:
        pass
    return urls

def analyze_image_bytes(content: bytes) -> tuple[set[str], str]:
    """
    Extracts URLs from image bytes using OCR (if available) and EXIF metadata.
    Returns: (set(urls), raw_ocr_text)
    """
    urls = set()
    text = ""
    try:
        img = Image.open(io.BytesIO(content))
        
        # 1. OCR
        if is_tesseract_available():
            try:
                # Basic optimization for OCR
                if img.width > 4000 or img.height > 4000:
                    img.thumbnail((2000, 2000))
                
                text = pytesseract.image_to_string(img)
                urls.update(re.findall(URL_REGEX, text))
            except Exception as e:
                logger.warning(f"OCR failed for image bytes: {e}")
        
        # 2. METADATA
        exif = img.getexif()
        if exif:
            for tag_id in exif:
                tag = exif.get(tag_id)
                if isinstance(tag, str):
                    urls.update(re.findall(URL_REGEX, tag))
                    text += f"\n[EXIF] {tag}"
                    
    except Exception as e:
        logger.error(f"Error processing image bytes: {e}")
        
    return urls, text

def analyze_image(path: str) -> set:
    """
    Extracts URLs from an image file path.
    """
    if not os.path.exists(path): return set()
    try:
        with open(path, "rb") as f:
            urls, _ = analyze_image_bytes(f.read())
            return urls
    except Exception:
        return set()
