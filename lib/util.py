import binascii

def b64_encode(buf):
    return binascii.b2a_base64(buf, newline=False).decode()

def chunk(vec, size):
    for i in range(0, len(vec), size):
        yield vec[i:i+size]
