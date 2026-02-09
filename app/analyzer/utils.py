import re
import urllib.parse
import html

def decode_proofpoint_url(url: str) -> str:
    """
    Decodes Proofpoint Urldefense (v1, v2, v3) URLs to their original target.
    Returns the original URL if not a Proofpoint link or if decoding fails.
    """
    # Quick check
    if "urldefense" not in url:
        return url

    try:
        # v3: https://urldefense.com/v3/__TARGET__;!!...
        if "/v3/" in url:
            match = re.search(r'/v3/__(.+?)__;!!', url)
            if match:
                return match.group(1)
            # Fallback for some v3 variants without __...__;!! pattern
            # Sometimes it's just /v3/Url...
            
        # v2: https://urldefense.com/v2/url?u=TARGET&...
        elif "/v2/" in url:
            parsed = urllib.parse.urlparse(url)
            qs = urllib.parse.parse_qs(parsed.query)
            encoded = qs.get('u', [''])[0]
            if not encoded: return url
            
            # v2 mapping: 
            # - -> %
            # _ -> /
            # . -> + (sometimes, though standard says no)
            # Standard tr: tr '-_' '%/'
            trans = str.maketrans('-_', '%/')
            decoded_step1 = encoded.translate(trans)
            return urllib.parse.unquote(decoded_step1)

        # v1: https://urldefense.com/v1/url?u=TARGET&k=...
        elif "/v1/" in url:
            parsed = urllib.parse.urlparse(url)
            qs = urllib.parse.parse_qs(parsed.query)
            return qs.get('u', [url])[0]

    except Exception:
        pass

    return url
