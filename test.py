import re
import base64
import binascii

def is_xss(payload):
    patterns = [
        r'<img[^>]*onerror\s*=\s*["\'][^"\']*alert\([^\)]*\)[^"\']*["\']',
        r'<a[^>]*href\s*=\s*["\']javascript:[^"\']*alert\([^\)]*\)[^"\']*["\']',
        r'<script[^>]*>[^<]*alert\([^\)]*\)[^<]*</script>',
        r'<script[^>]*>[^<]*eval\([^\)]*\)[^<]*</script>',
        r'<script[^>]*>[^<]*setTimeout\([^\)]*\)[^<]*</script>',
        r'<svg[^>]*onload\s*=\s*["\'][^"\']*alert\([^\)]*\)[^"\']*["\']',
        r'alert\([^)]*\)\s*=\s*eval\(\s*atob\([^\)]*\)[^)]*\)',
        r'on\w+\s*=\s*["\'][^"\']*alert\([^\)]*\)[^"\']*["\']',
        r'<input[^>]*onfocus\s*=\s*["\'][^"\']*alert\([^\)]*\)[^"\']*["\']',
        r'<object[^>]*data\s*=\s*["\']javascript:[^"\']*alert\([^\)]*\)[^"\']*["\']',
        r'<iframe[^>]*src\s*=\s*["\']blob:[^"\']*["\']',
        r'<iframe[^>]*src\s*=\s*["\']data:text/html;base64,[^"\']*["\']',
        r'<iframe[^>]*sandbox\s*=\s*["\'][^"\']*["\']src\s*=\s*["\']javascript:[^"\']*["\']',
        r'[\x00-\x7F]{4,}',
        r'document\.write\([^)]*\)',
        r'document\.createElement\([^)]*\)',
        r'window\.location\s*=\s*["\']javascript:[^"\']*["\']'
    ]
    
    for pattern in patterns:
        if re.search(pattern, payload, re.IGNORECASE):
            return True

    try:
        decoded_payload = base64.b64decode(payload.strip(), validate=True).decode('utf-8')
        if 'alert(' in decoded_payload:
            return True
    except (binascii.Error, UnicodeDecodeError):
        pass

    hex_pattern = r'\\x[0-9a-fA-F]{2}'
    if re.search(hex_pattern, payload):
        try:
            decoded_payload = bytes.fromhex(payload.replace('\\x', '')).decode('utf-8')
            if 'alert(' in decoded_payload:
                return True
        except ValueError:
            pass

    return False

payloads = [
    '<img src="x" onerror="alert(\'XSS\')">',
    '<a href="javascript:alert(\'XSS\')">Click me</a>',
    '<svg/onload=alert(\'XSS\')>',
    '<iframe srcdoc="<script>alert(\'XSS\')</script>"></iframe>',
    '<script>eval(atob(\'YWxlcnQoJ1hTUyc=\') )</script>',
    '<img src="x" onerror="this.onerror=null;alert(\'XSS\')">',
    '<iframe src="blob:http://example.com/abc123"></iframe>',
    'alert(1)=eval(atob(\'YWxlcnQoJ1hTUyc=\'))',
    '<script>document.domain = "evil.com"; alert(\'XSS\');</script>',
    '<input onfocus="alert(\'XSS\')">',
    '<iframe sandbox="allow-scripts" src="javascript:alert(\'XSS\')"></iframe>',
    '<object data="javascript:alert(\'XSS\')"></object>',
    'document.write(\'<script>alert("XSS")</script>\');'
]

for payload in payloads:
    result = is_xss(payload)
    print(f"Payload: {payload} -> XSS Detected: {result}")
