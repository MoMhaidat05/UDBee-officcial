import random
import struct

def fragment_message(message_bytes, chunk_size):
    """
    Splits bytes into chunks with binary header: [SessionID][Index][Total][Data]
    """
    chunks = []
    
    # Generate Session ID (2 bytes)
    session_id = random.randint(0, 65535)
    
    # Calculate payload size per chunk (Chunk Size - 6 bytes header)
    header_size = 6 # 2 (ID) + 2 (Index) + 2 (Total)
    data_per_chunk = chunk_size - header_size
    
    if data_per_chunk <= 0:
        raise ValueError("Chunk size too small for header")

    total = (len(message_bytes) + data_per_chunk - 1) // data_per_chunk
    
    for i in range(total):
        start = i * data_per_chunk
        end = min(start + data_per_chunk, len(message_bytes))
        part = message_bytes[start:end]
        
        # Pack Binary Header
        # !HHH = Network Order (Big Endian), Unsigned Short (2 bytes) x 3
        header = struct.pack('!HHH', session_id, i, total)
        
        full_chunk = header + part
        chunks.append(full_chunk)
    
    return chunks