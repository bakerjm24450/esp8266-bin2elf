import argparse
import os.path
import struct
import functools

BIN_MAGICNUMBER_V1 = b'\xe9'
BIN_MAGICNUMBER_V2 = b'\xea'

def readChecksum(f):
    """ Read the checksum byte from the file. The checksum is always
    at the last byte before a 16-byte address offset so we may need
    to skip some bytes in the file to reach the checksum.
    """
    position = f.tell()

    # figure out how many bytes to skip to reach the checksum
    bytesToSkip = 15 - (position % 16)
    f.read(bytesToSkip)

    # now read the checksum
    return ord(f.read(1))

def calculateChecksum(segments):
    """ Calculate the checksum for the data segments. The checksum value
    is the XOR of all data in the segments with the value 0xef
    """
    csum = 0xef

    for seg in segments:
        csum = functools.reduce(lambda x, y: x ^ y, seg["data"], csum)

    return csum


def readBinImageV1(f, segments=None):
    """ Read a version 1 bin file. The header has the following structure:
            Magic number (1 byte, always 0xe9)
            Number of segments (1 byte, should be <= 16)
            SPI config (2 bytes, values are not important for us)
            Entry point address (4 bytes, little-endian ordering)
        On entry, the magic number has already been consumed from the file, so 
        procesing begins with the number of segments
        Returns a tuple of (entryAddres, segments) where segments
        is a list of dictionaries, each entry with address and data
    """

    (segmentCount, _, entryAddress) = struct.unpack('<BHI', f.read(7))

    # verify the number of segments
    if segmentCount == 0 or segmentCount > 16:
        filePosition = f.tell() - 8         # -8 to account for header
        print('INFO: Found potential V1 header at offset 0x%x but invalid number of segments = %d' % (filePosition, segmentCount))
        return (0, None)

    if segments is None and segmentCount > 0:
        segments = []           # list of segments

    # read the segment headers and data
    for _ in range(segmentCount):
        (address, size) = struct.unpack('<II', f.read(8))
        data = f.read(size)

        if len(data) != size:
            print('Warning: End of file reached while reading segment data')
            return (0, None)

        segments.append({"address": address, "data": data})

    # see if checksums are ok
    if readChecksum(f) == calculateChecksum(segments):
        return (entryAddress, segments)
    else:
        print("Warning: Found possible V1 file but checksum is incorrect -- discarding")
        return (0, None)

def readBinImageV2(f):
    """ Read a version2 bin file. The header has the following structure:
            Magic number (1 byte, always 0xea)
            Magic value 2 (1 byte, always 0x4)
            SPI config (2 bytes, values are not important for us)
            Entry point address (4 bytes, little-endian ordering)
            Unused (4 bytes)
            Size of IROM segment (4 bytes)

        On entry, the magic number has already been read from the file, so
        processing begins with Magic value 2. 
        The header is followed by the data from the IROM text segment. The IROM
        segment has an implied address of 0x40200000. Immediately following
        the IROM data should a V1 header structure and the associated segments.
        Returns a tuple of (entryAddress, segments), where segments is a list of
        dictionaries, each containing the address, size, and data f
    """

    BIN_MAGIC2_V2 = 0x04
    IROM_ADDRESS = 0x40200000

    # read rest of header
    (magic2, _, entryAddress) = struct.unpack('<BHI', f.read(7))    

    if magic2 != BIN_MAGIC2_V2:
        filePosition = f.tell() - 8         # -8 to account for header
        print('INFO: Found potential V2 header at offset 0x%x but has improper magic number %d' % (filePosition, magic2))
        return (0, None)
    
    # read size of irom data
    (_, v2_size) = struct.unpack('<II', f.read(8))

    # read the irom data
    irom_data = f.read(v2_size)

    segments = []
    segments.append({"address": IROM_ADDRESS, "data": irom_data})

    # next byte should be a V1 header
    c = f.read(1)
    if c != BIN_MAGICNUMBER_V1:
        print('Warning: Found V2 file but missing accompanying Version 1 header')
        return (0, None)
    
    # read the version 1 file info
    (v1_entryAddress, v1_segments) = readBinImageV1(f)

    # verify that entry addresses are the same for both headers
    if v1_entryAddress != entryAddress:
        print('Warning: Found V2 file but entry address does not match V1 header.')
        return (0, None)
    
    else:
        # add V1 segments to segment list
        segments += v1_segments
        return (entryAddress, segments)


    

def readBinImage(f, version):
    """ Reads a bin program image from the filestream f. The version value
    specifies the format of the bin file (version 1 or version 2 of ESP8266). 
    Returns a tuple of (entry address, list of segments). If this is not the 
    beginning of a valid bin image, then it returns (0, None)
    """
    
    if version == BIN_MAGICNUMBER_V1:
        return readBinImageV1(f)
    elif version == BIN_MAGICNUMBER_V2:
        return readBinImageV2(f)
    else:
        return (0, None)          # not a valid bin image



def writeElfFile(elfname, entryAddr, segments):
    """ Writes an ELF file with the given name. Note this file will only 
    contain the ELF header, the program header table, and the segment data. There
    is no section header or string table.
    """
    with open(elfname, mode="wb") as f:
        # write ELF header
        elfHeader = struct.pack('<4s5B7x2H5I6H',
                                b"\x7fELF",
                                1,              # 32-bit
                                1,              # little-endian
                                1,              # version
                                0,              # target os
                                0,              # abi version
                                0x02,           # executable file
                                0x005e,         # Xtensa
                                1,              # version
                                entryAddr,
                                0x34,           # offset to program header table
                                0,              # offset to section header table
                                0x300,          # flags
                                0x34,           # size of elf header
                                0x20,           # size of program header entry
                                len(segments),
                                0x28,           # size of section header entry
                                0,              # number of sections
                                0)              # index to string header table
        f.write(elfHeader)

        # write program header table
        offset = 0x34 + len(segments) * 0x20
        for segment in segments:
            segmentEntry = struct.pack('<8I',
                                       0x1,     # loadable
                                       offset,
                                       segment["address"],
                                       segment["address"],
                                       len(segment["data"]),
                                       len(segment["data"]),
                                       0x7,     # flags
                                       0        # alignment
                                       )
            f.write(segmentEntry)

            offset += len(segment["data"])
        
        # write segments
        for segment in segments:
            f.write(segment["data"])


def extractBinFiles(filename):
    """ Extracts all bin images from a file by scanning the data
    byte-by-byte searching for a BIN header structure. Whenever
    one is found, the file is extracted and written to an ELF file.
    """

    # open file and process it
    with open(filename, mode="rb") as f:
        fileCount = 0           # used for generating unique filenames

        segments = []           # list of segments

        # read bytes until we find magic number (or hit EOF)
        while True:
            c = f.read(1)

            # EOF?
            if c == b'':
                return
            
            else:
                # try to read bin file
                (entry, segments) = readBinImage(f, c)

                # if valid, then write a new ELF file
                if segments is not None:
                    # build elf file name
                    elfname = os.path.splitext(filename)[0] + str(fileCount) + ".elf"
                    writeElfFile(elfname, entry, segments)

                    # increment file count
                    fileCount += 1


def main():
    # parse the command line arguments
    parser = argparse.ArgumentParser(description="Convert ESP8266 bin file to ELF file(s)")
    parser.add_argument("filename")

    args = parser.parse_args()

    # process the file
    extractBinFiles(args.filename)




if __name__ == "__main__":
    main()