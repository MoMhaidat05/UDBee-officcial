import random
import struct

def fragment_message(message_bytes, chunk_size):
    """
    Splits bytes into chunks with binary header: [SessionID][Index][Total][Data]
    """
    # لا تقم بتحويل message_bytes إلى str هنا أبداً!
    
    chunks = []
    
    # Generate Session ID (2 bytes)
    session_id = random.randint(0, 65535)
    
    # Calculate payload size per chunk (Chunk Size - 6 bytes header)
    header_size = 6 
    data_per_chunk = chunk_size - header_size
    
    # حماية من القسمة على صفر
    if data_per_chunk <= 0:
        data_per_chunk = 1 

    total = (len(message_bytes) + data_per_chunk - 1) // data_per_chunk
    
    for i in range(total):
        start = i * data_per_chunk
        end = min(start + data_per_chunk, len(message_bytes))
        
        # Slicing bytes returns bytes
        part = message_bytes[start:end]
        
        # Pack Binary Header (Bytes)
        header = struct.pack('!HHH', session_id, i, total)
        
        # Bytes + Bytes = Valid
        full_chunk = header + part
        chunks.append(full_chunk)
    
    return chunks