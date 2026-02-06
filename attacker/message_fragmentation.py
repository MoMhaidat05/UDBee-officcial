import random
import struct

def fragment_message(message_bytes, chunk_size):
    """
    Splits bytes into chunks with binary header: [Index][Total][Data]
    Session ID is returned separately to be used as DNS Transaction ID.
    
    Returns: (session_id, chunks_list)
    """
    chunks = []
    
    # Generate Session ID (will be used as DNS Transaction ID)
    session_id = random.randint(0, 65535)
    
    # Calculate payload size per chunk (Chunk Size - 4 bytes header: Index + Total)
    header_size = 4  # 2 (Index) + 2 (Total)
    data_per_chunk = chunk_size - header_size
    
    if data_per_chunk <= 0:
        raise ValueError("Chunk size too small for header")

    total = (len(message_bytes) + data_per_chunk - 1) // data_per_chunk
    
    for i in range(total):
        start = i * data_per_chunk
        end = min(start + data_per_chunk, len(message_bytes))
        part = message_bytes[start:end]
        
        # Pack Binary Header: Index (2 bytes) + Total (2 bytes)
        # !HH = Network Order (Big Endian), Unsigned Short (2 bytes) x 2
        header = struct.pack('!HH', i, total)
        
        full_chunk = header + part
        chunks.append(full_chunk)
    
    return session_id, chunks