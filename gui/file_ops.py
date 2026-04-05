import os
import re
import hashlib
from config import CHUNK_SIZE, HEADER_SIZE

class MultiFileReader:
    def __init__(self, paths):
        self.paths = paths
        self.idx = 0
        self.f = open(self.paths[self.idx], 'rb')
        
    def read(self, size):
        res = bytearray()
        while len(res) < size:
            chunk = self.f.read(size - len(res))
            res.extend(chunk)
            if not chunk:
                self.f.close()
                self.idx += 1
                if self.idx < len(self.paths):
                    self.f = open(self.paths[self.idx], 'rb')
                else:
                    break
        return bytes(res)
        
    def seek_to_payload(self):
        self.f.close()
        self.idx = 0
        self.f = open(self.paths[self.idx], 'rb')
        self.f.seek(HEADER_SIZE)
        
    def close(self):
        try: self.f.close()
        except: pass

def get_parts(base_path):
    clean_path = re.sub(r'\.part\d{3}$', '', str(base_path))
    if os.path.exists(clean_path):
        return [clean_path]
        
    parts = []
    i = 1
    while True:
        part_name = f"{clean_path}.part{i:03d}"
        if os.path.exists(part_name):
            parts.append(part_name)
            i += 1
        else:
            break
            
    if not parts:
        raise FileNotFoundError(f"File or parts not found: {clean_path}")
    return parts

def secure_shred_file(file_base_path, progress_callback=None):
    try:
        parts = get_parts(file_base_path)
        total_shred_size = sum(os.path.getsize(p) for p in parts)
        shredded_bytes = 0
        
        for part in parts:
            part_size = os.path.getsize(part)
            with open(part, "ba+", buffering=0) as f:
                f.seek(0)
                written = 0
                while written < part_size:
                    write_size = min(CHUNK_SIZE, part_size - written)
                    f.write(os.urandom(write_size))
                    written += write_size
                    shredded_bytes += write_size
                    
                    if progress_callback:
                        pct = (shredded_bytes / total_shred_size) if total_shred_size > 0 else 1.0
                        progress_callback(pct)
                    
            directory = os.path.dirname(part)
            random_name = os.path.join(directory, os.urandom(8).hex() + ".tmp")
            os.rename(part, random_name)
            os.remove(random_name)
    except Exception as e:
        raise Exception(f"Shredding failed: {str(e)}")

def compare_files(file1, file2):
    with open(file1, 'rb') as f1, open(file2, 'rb') as f2:
        while True:
            b1, b2 = f1.read(4096), f2.read(4096)
            if b1 != b2:
                return False
            if not b1: break
    return True

def calculate_file_hash(file_path):
    h = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while True:
            chunk = f.read(CHUNK_SIZE)
            if not chunk: break
            h.update(chunk)
    return h.hexdigest()