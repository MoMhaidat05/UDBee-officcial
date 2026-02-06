"""Test CVC Codec v2.2 - Short labels (3-6 chars)"""
import sys, os

sys.path.insert(0, 'attacker')
import cvc_codec as attacker_codec
sys.path.pop(0)

del sys.modules['cvc_codec']
sys.path.insert(0, 'victim')
import cvc_codec as victim_codec
sys.path.pop(0)

print("=== CVC Codec v2.2 Short-Label Test ===\n")

# Test 1: Label length compliance
print("Test 1: Label length (target: 3-6 chars per payload label)")
for size in [5, 10, 15]:
    data = os.urandom(size)
    enc = attacker_codec.encode_bytes_to_domain(data)
    parts = enc.split('.')
    payload_labels = [p for p in parts if len(p) in (3, 6)]
    all_labels = [len(p) for p in parts]
    dec = attacker_codec.decode_domain_to_bytes(enc)
    print(f"  {size:2d}B -> {len(parts)} labels, sizes={all_labels}")
    print(f"    Domain: {enc}")
    print(f"    Decode: {'OK' if dec == data else 'FAIL'}")

# Test 2: Max label length check  
print("\nTest 2: Max label length (100 random 15-byte chunks)")
max_seen = 0
violations = 0
for _ in range(100):
    data = os.urandom(15)
    enc = attacker_codec.encode_bytes_to_domain(data)
    for label in enc.split('.'):
        if len(label) > max_seen:
            max_seen = len(label)
        # Only check CVC-looking labels, not template parts like "cloudflare"
        if len(label) <= 6 or label in ('cloudflare', 'akamaihd', 'cloudfront', 
                                         'fastly', 'static', 'data', 'org', 'io'):
            continue
        # Template labels are fine, just CVC payload should be <=6
        if len(label) % 3 == 0 and all(
            label[i] in 'bcdfghjklmnprstvwxz' and 
            label[i+1] in 'aeiouy' and 
            label[i+2] in 'bcdfgklmnprstxz' 
            for i in range(0, len(label), 3)
        ):
            violations += 1
print(f"  Max label seen: {max_seen} chars")
print(f"  CVC labels > 6 chars: {violations}")

# Test 3: Average label length  
print("\nTest 3: Average payload label length (target: ~4.5)")
total_len = 0
total_count = 0
for _ in range(200):
    data = os.urandom(15)
    enc = attacker_codec.encode_bytes_to_domain(data)
    for label in enc.split('.'):
        if len(label) in (3, 6):  # CVC payload labels
            total_len += len(label)
            total_count += 1
if total_count > 0:
    print(f"  Average: {total_len/total_count:.1f} chars ({total_count} labels sampled)")

# Test 4: Domain total length stats
print("\nTest 4: Domain total length distribution")
lengths = []
for _ in range(200):
    data = os.urandom(15)
    enc = attacker_codec.encode_bytes_to_domain(data)
    lengths.append(len(enc))
avg_len = sum(lengths) / len(lengths)
min_len = min(lengths)
max_len = max(lengths)
print(f"  Min: {min_len}, Max: {max_len}, Avg: {avg_len:.1f}")

# Test 5: Round-trip all sizes (attacker)
print("\nTest 5: Round-trip (attacker codec)")
failed = 0
for size in [3, 5, 8, 10, 12, 15, 20, 30]:
    data = os.urandom(size)
    enc = attacker_codec.encode_bytes_to_domain(data)
    dec = attacker_codec.decode_domain_to_bytes(enc)
    ok = dec == data
    if not ok: failed += 1
    print(f"  {size:2d}B: {'OK' if ok else 'FAIL'} ({len(enc.split('.'))} labels, {len(enc)} chars)")
print(f"  Result: {8-failed}/8")

# Test 6: Round-trip victim codec
print("\nTest 6: Round-trip (victim codec)")
failed = 0
for size in [3, 5, 8, 10, 12, 15, 20, 30]:
    data = os.urandom(size)
    enc = victim_codec.encode_bytes_to_domain(data)
    dec = victim_codec.decode_domain_to_bytes(enc)
    ok = dec == data
    if not ok: failed += 1
    print(f"  {size:2d}B: {'OK' if ok else 'FAIL'} ({len(enc.split('.'))} labels, {len(enc)} chars)")
print(f"  Result: {8-failed}/8")

# Test 7: Cross-compatibility
print("\nTest 7: Cross-compat (victim->attacker, 50 rounds)")
failed = 0
for _ in range(50):
    data = os.urandom(15)
    enc = victim_codec.encode_bytes_to_domain(data)
    dec = attacker_codec.decode_domain_to_bytes(enc)
    if dec != data: failed += 1
print(f"  Result: {50-failed}/50")

print("\nTest 8: Cross-compat (attacker->victim, 50 rounds)")
failed = 0
for _ in range(50):
    data = os.urandom(15)
    enc = attacker_codec.encode_bytes_to_domain(data)
    dec = victim_codec.decode_domain_to_bytes(enc)
    if dec != data: failed += 1
print(f"  Result: {50-failed}/50")

# Test 9: Sample domains  
print("\nTest 9: Sample domains (15-byte chunks)")
for i in range(8):
    data = os.urandom(15)
    enc = attacker_codec.encode_bytes_to_domain(data)
    print(f"  {enc}")
