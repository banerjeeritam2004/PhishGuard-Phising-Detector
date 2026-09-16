"""Generate simple placeholder PNG icons for the extension."""
import struct, zlib, os

def make_png(size, r, g, b):
    """Create a minimal valid PNG of solid color."""
    def chunk(name, data):
        c = struct.pack('>I', len(data)) + name + data
        return c + struct.pack('>I', zlib.crc32(c[4:]) & 0xffffffff)
    
    ihdr = struct.pack('>IIBBBBB', size, size, 8, 2, 0, 0, 0)
    raw = b''
    for _ in range(size):
        row = b'\x00' + bytes([r, g, b] * size)
        raw += row
    
    png = b'\x89PNG\r\n\x1a\n'
    png += chunk(b'IHDR', ihdr)
    png += chunk(b'IDAT', zlib.compress(raw))
    png += chunk(b'IEND', b'')
    return png

os.makedirs("icons", exist_ok=True)
for size in [16, 48, 128]:
    data = make_png(size, 239, 68, 68)  # Red #ef4444
    with open(f"icons/icon{size}.png", "wb") as f:
        f.write(data)
    print(f"Created icon{size}.png")
