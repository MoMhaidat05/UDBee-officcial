"""Test CVC Codec v2.1 - Compact domains (4-6 labels)"""
import sys, os

# Test attacker codec
sys.path.insert(0, 'attacker')
import cvc_codec as attacker_codec
sys.path.pop(0)

# Test victim codec  
del sys.modules['cvc_codec']
sys.path.insert(0, 'victim')
import cvc_codec as victim_codec
sys.path.pop(0)

print("=== CVC Codec v2.1 Compact Test ===\n")

# Test 1: Label count  
print("Test 1: Label count (target: 4-6)")
for size in [8, 14, 19, 23]:
    data = os.urandom(size)
    enc = attacker_codec.encode_bytes_to_domain(data)
    labels = len(enc.split('.'))
    dec = attacker_codec.decode_domain_to_bytes(enc)
    print(f"  {size:2d} bytes -> {labels} labels, decode: {'OK' if dec == data else 'FAIL'}")
    print(f"    {enc[:90]}{'...' if len(enc) > 90 else ''}")

# Test 2: Round-trip all sizes
print("\nTest 2: Round-trip (attacker codec)")
failed = 0
for size in [5, 10, 15, 19, 23, 30, 50]:
    data = os.urandom(size)
    enc = attacker_codec.encode_bytes_to_domain(data)
    dec = attacker_codec.decode_domain_to_bytes(enc)
    ok = dec == data
    if not ok: failed += 1
    print(f"  {size:2d} bytes: {'OK' if ok else 'FAIL'} ({len(enc.split('.'))} labels)")
print(f"  Result: {7-failed}/7 passed")

# Test 3: Round-trip victim codec
print("\nTest 3: Round-trip (victim codec)")
failed = 0
for size in [5, 10, 15, 19, 23, 30, 50]:
    data = os.urandom(size)
    enc = victim_codec.encode_bytes_to_domain(data)
    dec = victim_codec.decode_domain_to_bytes(enc)
    ok = dec == data
    if not ok: failed += 1
    print(f"  {size:2d} bytes: {'OK' if ok else 'FAIL'} ({len(enc.split('.'))} labels)")
print(f"  Result: {7-failed}/7 passed")

# Test 4: Cross-compatibility (victim encodes, attacker decodes)
print("\nTest 4: Cross-compat (victim->attacker)")
failed = 0
for i in range(20):
    data = os.urandom(23)
    enc = victim_codec.encode_bytes_to_domain(data)
    dec = attacker_codec.decode_domain_to_bytes(enc)
    if dec != data:
        failed += 1
        print(f"  FAIL [{i}]: {enc[:60]}")
print(f"  Result: {20-failed}/20 passed")

# Test 5: Cross-compatibility (attacker encodes, victim decodes)
print("\nTest 5: Cross-compat (attacker->victim)")
failed = 0
for i in range(20):
    data = os.urandom(23)
    enc = attacker_codec.encode_bytes_to_domain(data)
    dec = victim_codec.decode_domain_to_bytes(enc)
    if dec != data:
        failed += 1
        print(f"  FAIL [{i}]: {enc[:60]}")
print(f"  Result: {20-failed}/20 passed")

# Test 6: Example domains for visual inspection
print("\nTest 6: Sample domains (23-byte chunks)")
for i in range(5):
    data = os.urandom(23)
    enc = attacker_codec.encode_bytes_to_domain(data)
    print(f"  [{i}] {enc}")
