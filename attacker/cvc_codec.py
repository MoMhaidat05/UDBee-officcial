import random
import string

# --- CVC Constants ---
C_START = ['b', 'c', 'd', 'f', 'g', 'h', 'j', 'k', 'l', 'm', 'n', 'p', 'r', 's', 't', 'v', 'w', 'x', 'z']
VOWELS = ['a', 'e', 'i', 'o', 'u', 'y']
C_END = ['b', 'c', 'd', 'f', 'g', 'k', 'l', 'm', 'n', 'p', 'r', 's', 't', 'x', 'z']

# --- SAFE Templates ---
# CRITICAL: All template words must NOT match CVC pattern!
# Safe patterns:
#   - Words starting with vowels (a,e,i,o,u,y) -> first char not in C_START
#   - Words with consecutive consonants that break CVC (e.g., 'str', 'cdn')
#   - Single/two letter words
# Data delimiter: 'xx' marks start and end of data section for unambiguous parsing
TEMPLATES = [
    "ip.xx.{0}.xx.eu",           # 'ip','eu' start with vowel -> Safe, 'xx' is delimiter
    "a1.xx.{0}.xx.io",           # 'a1' starts with vowel -> Safe
    "id.xx.{0}.xx.us",           # 'id','us' start with vowel -> Safe  
    "up.xx.{0}.xx.uk",           # 'up','uk' start with vowel -> Safe
    "e0.xx.{0}.xx.az",           # 'e0','az' start with vowel -> Safe
]

# Data section delimiter - used to isolate payload from template noise
DATA_DELIMITER = 'xx'

# Words to ignore during decoding (fallback safety net)
# Includes TLDs, common DNS prefixes, and any template fragments
# NOTE: Do NOT add valid CVC patterns here! They could be generated as data.
# 'com' was removed because c-o-m is a valid CVC syllable.
# 'net' was removed because n-e-t is a valid CVC syllable.
IGNORE_WORDS = {
    # TLDs (only non-CVC ones - 'net' removed, it's valid CVC)
    'org', 'io', 'eu', 'us', 'uk', 'az', 'co',
    # Common DNS prefixes (non-CVC)
    'www', 'ftp', 'ns1', 'ns2', 'mail', 'smtp', 'api', 'cdn', 'dns',
    # Template fragments (all should start with vowel or be non-CVC anyway)
    'ip', 'a1', 'id', 'up', 'e0', 'v1', 'db',
    # Delimiter
    'xx',
}

def _value_to_syllable(value_10bit):
    """Internal: Convert 10-bit integer to CVC syllable"""
    idx_end = value_10bit % 15
    rem = value_10bit // 15
    idx_vow = rem % 6
    rem = rem // 6
    idx_start = rem % 19
    return f"{C_START[idx_start]}{VOWELS[idx_vow]}{C_END[idx_end]}"

def encode_bytes_to_domain(raw_data: bytes) -> str:
    if not raw_data: return ""
    
    # Prepend 1-byte length to preserve exact byte count during decode
    # This handles the bit-alignment padding issue
    length_byte = bytes([len(raw_data)])
    data_with_length = length_byte + raw_data
    
    huge_int = int.from_bytes(data_with_length, 'big')
    total_bits = len(data_with_length) * 8
    num_chunks = (total_bits + 9) // 10
    
    cvc_list = []
    for _ in range(num_chunks):
        chunk_val = huge_int & 0x3FF 
        cvc_list.append(_value_to_syllable(chunk_val))
        huge_int >>= 10
        
    cvc_list.reverse()
    
    labels = []
    current_group = ""
    for i, cvc in enumerate(cvc_list):
        current_group += cvc
        if (i + 1) % 3 == 0:
            labels.append(current_group)
            current_group = ""
    if current_group:
        labels.append(current_group)
        
    domain_core = ".".join(labels)
    template = random.choice(TEMPLATES)
    try:
        domain_name = template.format(domain_core)
    except:
        # Safe fallback: 'a0' and 'io' don't match CVC pattern
        domain_name = f"a0.xx.{domain_core}.xx.io"

    return domain_name

# Alias
encode_packet_to_domain = encode_bytes_to_domain

def _is_valid_cvc(s: str) -> bool:
    """Check if a 3-char string is a valid CVC syllable."""
    if len(s) != 3:
        return False
    return s[0] in C_START and s[1] in VOWELS and s[2] in C_END


def _extract_data_between_delimiters(parts: list) -> list:
    """
    Extract only the parts between 'xx' delimiters.
    This isolates the actual data from template noise.
    """
    try:
        first_xx = parts.index(DATA_DELIMITER)
        last_xx = len(parts) - 1 - parts[::-1].index(DATA_DELIMITER)
        if first_xx < last_xx:
            return parts[first_xx + 1 : last_xx]
    except ValueError:
        pass
    # Fallback: return all parts if delimiters not found
    return parts


def decode_domain_to_bytes(domain_string: str, debug=False) -> bytes:
    """
    Decodes a CVC domain back to bytes.
    Uses delimiter-based parsing to isolate data from template noise.
    """
    clean_parts = domain_string.lower().split('.')
    
    # Step 1: Extract data section between delimiters
    data_parts = _extract_data_between_delimiters(clean_parts)
    
    if debug:
        print(f"[DEBUG] clean_parts: {clean_parts}")
        print(f"[DEBUG] data_parts: {data_parts}")
    
    syllables = []
    
    for part in data_parts:
        # Skip ignored words (safety net)
        if part in IGNORE_WORDS:
            if debug: print(f"[DEBUG] Skipping ignored: {part}")
            continue
        
        # Skip parts that aren't multiples of 3 (can't contain complete CVCs)
        if len(part) == 0 or len(part) % 3 != 0:
            if debug: print(f"[DEBUG] Skipping non-mod3: {part} (len={len(part)})")
            continue
            
        # Extract CVC syllables from this part
        for i in range(0, len(part), 3):
            sub = part[i:i+3]
            if _is_valid_cvc(sub) and sub not in IGNORE_WORDS:
                syllables.append(sub)
            elif debug:
                print(f"[DEBUG] Invalid CVC or ignored: {sub}")
    
    if debug:
        print(f"[DEBUG] syllables: {syllables}")
    
    if not syllables:
        return b""

    # Reconstruct the integer from syllables
    # Syllables are in MSB-first order (encoder reversed them), so process left-to-right
    huge_int = 0
    
    for syl in syllables:  # NO reverse - domain order is already MSB first
        try:
            idx_start = C_START.index(syl[0])
            idx_vow = VOWELS.index(syl[1])
            idx_end = C_END.index(syl[2])
            val_10bit = (idx_start * 90) + (idx_vow * 15) + idx_end
            huge_int = (huge_int << 10) | val_10bit
        except ValueError:
            continue 

    # Convert integer to bytes - use minimum bytes needed (no padding)
    if huge_int == 0:
        return b""
    
    # Calculate minimum bytes needed for the integer
    byte_length = (huge_int.bit_length() + 7) // 8
    decoded_with_length = huge_int.to_bytes(byte_length, 'big')
    
    if debug:
        print(f"[DEBUG] huge_int hex: {hex(huge_int)}")
        print(f"[DEBUG] byte_length: {byte_length}")
        print(f"[DEBUG] decoded_with_length: {decoded_with_length.hex()}")
    
    # Extract length prefix and return exact original data
    if len(decoded_with_length) < 1:
        return b""
    
    original_length = decoded_with_length[0]
    original_data = decoded_with_length[1:1 + original_length]
    
    if debug:
        print(f"[DEBUG] length_prefix: {original_length}, returning {len(original_data)} bytes")
    
    return original_data