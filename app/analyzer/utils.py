import re
import urllib.parse

def decode_proofpoint_url(url: str) -> str:
    """
    Decodes Proofpoint Urldefense (v1, v2, v3) URLs to their original target.
    Returns the original URL if not a Proofpoint link or if decoding fails.
    """
    if "urldefense.proofpoint.com" not in url and "urldefense.com" not in url:
        return url

    try:
        # 1. Detect Version & Extract
        if "/v1/url" in url:
            # v1: Query param 'u'
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            return params.get('u', [url])[0]

        elif "/v2/url" in url:
            # v2: Query param 'u' with custom character mapping
            # Mapping: '-' -> '%' (for hex encoding), then unquote, but proofpoint uses specific ones:
            # '-' followed by 2 hex chars -> unquote
            # '_' -> '/'
            parsed = urllib.parse.urlparse(url)
            params = urllib.parse.parse_qs(parsed.query)
            encoded_url = params.get('u', [None])[0]
            if not encoded_url:
                return url
            
            # v2 characters: '-' is escape for hex, '_' is '/'
            # Step 1: Replace _ with /
            step1 = encoded_url.replace('_', '/')
            # Step 2: Replace - with % to use standard unquote
            step2 = step1.replace('-', '%')
            return urllib.parse.unquote(step2)

        elif "/v3/" in url:
            # v3: Target is inside __ and __
            # e.g. https://urldefense.com/v3/__https://example.com__;!!ABC!DEF
            match = re.search(r'/v3/__(.*?)__', url)
            if match:
                return match.group(1)
            
            # Alt v3 format? Some use query params or different segments
            # For now, __ is the most common v3 indicator
    except Exception:
        pass

    return url
