"""
Vexor Decoder — Encode/Decode utility
"""
import base64
import urllib.parse
import html
import binascii
import json
import hashlib
from typing import Optional


class Decoder:
    """Multi-format encoder/decoder"""

    FORMATS = [
        'base64', 'url', 'html', 'hex', 'binary',
        'md5', 'sha1', 'sha256', 'sha512',
        'rot13', 'reverse', 'unicode',
    ]

    def decode(self, data: str, fmt: str) -> str:
        """Decode data from specified format"""
        try:
            if fmt == 'base64':
                padded = data + '=' * (4 - len(data) % 4)
                return base64.b64decode(padded).decode('utf-8', errors='replace')
            elif fmt == 'url':
                return urllib.parse.unquote(data)
            elif fmt == 'html':
                return html.unescape(data)
            elif fmt == 'hex':
                return bytes.fromhex(data.replace(' ', '').replace('0x', '')).decode('utf-8', errors='replace')
            elif fmt == 'binary':
                bits = data.replace(' ', '')
                chars = [bits[i:i+8] for i in range(0, len(bits), 8)]
                return ''.join(chr(int(b, 2)) for b in chars if len(b) == 8)
            elif fmt == 'rot13':
                return data.translate(str.maketrans(
                    'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz',
                    'NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm'
                ))
            elif fmt == 'reverse':
                return data[::-1]
            elif fmt == 'unicode':
                return data.encode().decode('unicode_escape')
            else:
                return f"Unknown format: {fmt}"
        except Exception as e:
            return f"Decode error: {str(e)}"

    def encode(self, data: str, fmt: str) -> str:
        """Encode data to specified format"""
        try:
            if fmt == 'base64':
                return base64.b64encode(data.encode()).decode()
            elif fmt == 'url':
                return urllib.parse.quote(data)
            elif fmt == 'html':
                return html.escape(data)
            elif fmt == 'hex':
                return data.encode().hex()
            elif fmt == 'binary':
                return ' '.join(format(ord(c), '08b') for c in data)
            elif fmt == 'md5':
                return hashlib.md5(data.encode()).hexdigest()
            elif fmt == 'sha1':
                return hashlib.sha1(data.encode()).hexdigest()
            elif fmt == 'sha256':
                return hashlib.sha256(data.encode()).hexdigest()
            elif fmt == 'sha512':
                return hashlib.sha512(data.encode()).hexdigest()
            elif fmt == 'rot13':
                return self.decode(data, 'rot13')
            elif fmt == 'reverse':
                return data[::-1]
            else:
                return f"Unknown format: {fmt}"
        except Exception as e:
            return f"Encode error: {str(e)}"

    def auto_detect(self, data: str) -> list[dict]:
        """Try to auto-detect and decode data"""
        results = []

        # Try base64
        try:
            padded = data + '=' * (4 - len(data) % 4)
            decoded = base64.b64decode(padded).decode('utf-8', errors='strict')
            if decoded.isprintable():
                results.append({'format': 'base64', 'result': decoded})
        except Exception:
            pass

        # Try URL encoding
        if '%' in data:
            results.append({'format': 'url', 'result': urllib.parse.unquote(data)})

        # Try HTML entities
        if '&' in data and ';' in data:
            results.append({'format': 'html', 'result': html.unescape(data)})

        # Try hex
        try:
            clean = data.replace(' ', '').replace('0x', '').replace('\\x', '')
            if all(c in '0123456789abcdefABCDEF' for c in clean) and len(clean) % 2 == 0:
                decoded = bytes.fromhex(clean).decode('utf-8', errors='strict')
                if decoded.isprintable():
                    results.append({'format': 'hex', 'result': decoded})
        except Exception:
            pass

        # Try JWT
        if data.count('.') == 2 and data.startswith('eyJ'):
            try:
                parts = data.split('.')
                header = base64.b64decode(parts[0] + '==').decode()
                payload = base64.b64decode(parts[1] + '==').decode()
                results.append({
                    'format': 'jwt',
                    'result': f"Header: {header}\nPayload: {payload}"
                })
            except Exception:
                pass

        return results
