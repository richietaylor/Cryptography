import hashlib

class fileManager:
    def __init__(self, filename: str, chunkSize=4096, write=False) -> None:
        self.filename = filename
        self.chunkSize = chunkSize
        b = 'rb'
        if write:
            b = 'wb'
        self.target = open(self.filename, b)
        self.chunk = chunkSize

    def getChunk(self): # Reads a chunk from a file of specified length
        chunk = self.target.read(self.chunkSize)
        self.chunk = len(chunk)
        return chunk

    def close(self):
        self.target.close()


def getChecksum(filename: str): # Returns the checksum of the specified file
    print(filename)
    hasher = hashlib.md5()
    with open(filename, 'rb') as open_file:
        content = open_file.read()
        hasher.update(content)
    return hasher.hexdigest()

