"""Test CVC Codec v2.3 - Shallow Depth (max 5 labels, 18-char payload labels)"""
import sys, os

sys.path.insert(0, 'attacker')
import cvc_codec as attacker_codec
sys.path.pop(0)

del sys.modules['cvc_codec']
sys.path.insert(0, 'victim')
import cvc_codec as victim_codec
sys.path.pop(0)

print("=== CVC Codec v2.3 Shallow Depth Test ===\n")

# Test 1: Label count (MUST be ≤ 5)
print("Test 1: Label count (target: max 5)")
violations = 0
for _ in range(200):
    data = os.urandom(19)
    enc = attacker_codec.encode_bytes_to_domain(data)
    parts = enc.split('.')
    if len(parts) > 5:
        violations += 1
        print(f"  VIOLATION: {len(parts)} labels: {enc}")
print(f"  200 domains tested, {violations} violations (target: 0)")

# Test 2: Payload label lengths (target: 10-18 chars)
print("\nTest 2: Payload label lengths (target: 10-18 chars)")
all_payload_lens = []
for _ in range(200):
    data = os.urandom(19)
    enc = attacker_codec.encode_bytes_to_domain(data)
    parts = enc.split('.')
    for p in parts:
        if len(p) >= 3 and len(p) % 3 == 0:
            # Check if all triplets are CVC
            is_cvc = all(
                p[i] in 'bcdfghjklmnprstvwxz' and p[i+1] in 'aeiouy' and p[i+2] in 'bcdfgklmnprstxz'
                for i in range(0, len(p), 3)
            )
            if is_cvc:
                all_payload_lens.append(len(p))
if all_payload_lens:
    print(f"  Min: {min(all_payload_lens)}, Max: {max(all_payload_lens)}, Avg: {sum(all_payload_lens)/len(all_payload_lens):.1f}")
    print(f"  Labels: {len(all_payload_lens)} sampled")

# Test 3: Round-trip (attacker codec)
print("\nTest 3: Round-trip (attacker codec)")
failed = 0
for size in [3, 5, 8, 10, 15, 19]:
    data = os.urandom(size)
    enc = attacker_codec.encode_bytes_to_domain(data)
    dec = attacker_codec.decode_domain_to_bytes(enc)
    ok = dec == data
    if not ok: failed += 1
    parts = enc.split('.')
    print(f"  {size:2d}B: {'OK' if ok else 'FAIL'} ({len(parts)} labels, {len(enc)} chars)")
    print(f"      {enc}")
print(f"  Result: {6-failed}/6")

# Test 4: Round-trip (victim codec)
print("\nTest 4: Round-trip (victim codec)")
failed = 0
for size in [3, 5, 8, 10, 15, 19]:
    data = os.urandom(size)
    enc = victim_codec.encode_bytes_to_domain(data)
    dec = victim_codec.decode_domain_to_bytes(enc)
    ok = dec == data
    if not ok: failed += 1
    parts = enc.split('.')
    print(f"  {size:2d}B: {'OK' if ok else 'FAIL'} ({len(parts)} labels, {len(enc)} chars)")
print(f"  Result: {6-failed}/6")

# Test 5: Cross-compat
print("\nTest 5: Cross-compat (victim->attacker, 100 rounds)")
failed = 0
for _ in range(100):
    data = os.urandom(19)
    enc = victim_codec.encode_bytes_to_domain(data)
    dec = attacker_codec.decode_domain_to_bytes(enc)
    if dec != data: failed += 1
print(f"  Result: {100-failed}/100")

print("\nTest 6: Cross-compat (attacker->victim, 100 rounds)")
failed = 0
for _ in range(100):
    data = os.urandom(19)
    enc = attacker_codec.encode_bytes_to_domain(data)
    dec = victim_codec.decode_domain_to_bytes(enc)
    if dec != data: failed += 1
print(f"  Result: {100-failed}/100")

# Test 7: Domain total length
print("\nTest 7: Domain total length distribution")
lengths = []
for _ in range(200):
    data = os.urandom(19)
    enc = attacker_codec.encode_bytes_to_domain(data)
    lengths.append(len(enc))
print(f"  Min: {min(lengths)}, Max: {max(lengths)}, Avg: {sum(lengths)/len(lengths):.1f}")

# Test 8: Sample domains
print("\nTest 8: Sample domains (19-byte chunks)")
for i in range(8):
    data = os.urandom(19)
    enc = attacker_codec.encode_bytes_to_domain(data)
    parts = enc.split('.')
    print(f"  [{i}] ({len(parts)} labels) {enc}")
