#!/usr/bin/env python3
"""Test script for CVC codec v2.0"""
import sys
sys.path.insert(0, 'attacker')

import cvc_codec
import struct

print("=== CVC Codec v2.0 Test ===\n")

# Test 1: Simple data
print("Test 1: Simple data")
d1 = b'test1234'
e1 = cvc_codec.encode_bytes_to_domain(d1)
dec1 = cvc_codec.decode_domain_to_bytes(e1)
print(f"  Original: {d1}")
print(f"  Encoded:  {e1}")
print(f"  Decoded:  {dec1}")
print(f"  Match:    {dec1 == d1}")
print()

# Test 2: Chunk with header (simulating real packet)
print("Test 2: Chunk with header (36 bytes)")
d2 = struct.pack('!HH', 0, 5) + b'X' * 32  # 4 byte header + 32 byte data
e2 = cvc_codec.encode_bytes_to_domain(d2)
dec2 = cvc_codec.decode_domain_to_bytes(e2)
print(f"  Original: {len(d2)} bytes")
print(f"  Encoded:  {e2[:80]}...")
print(f"  Decoded:  {len(dec2)} bytes")
print(f"  Match:    {dec2 == d2}")
print()

# Test 3: Multiple encodes to verify randomization
print("Test 3: Randomization (5 encodes of same data)")
test_data = struct.pack('!HH', 1, 10) + b'Hello!'
for i in range(5):
    enc = cvc_codec.encode_bytes_to_domain(test_data)
    dec = cvc_codec.decode_domain_to_bytes(enc)
    first_label = enc.split('.')[0]
    junk_labels = [l for l in enc.split('.') if any(c.isdigit() for c in l)]
    print(f"  [{i}] First: {first_label[:9]}... Junk: {junk_labels[0] if junk_labels else 'N/A'} Match: {dec == test_data}")
print()

# Test 4: Debug decode
print("Test 4: Debug decode")
d4 = b'\x00\x00\x00\x05TestData'
e4 = cvc_codec.encode_bytes_to_domain(d4)
print(f"  Domain: {e4}")
dec4 = cvc_codec.decode_domain_to_bytes(e4, debug=True)
print(f"  Match: {dec4 == d4}")
