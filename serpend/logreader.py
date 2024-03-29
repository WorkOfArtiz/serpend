#!/usr/bin/env python3
# -*- coding utf-8 -*-
"""
A module that reads in systemd's log format and defines a very basic API
over it.

We would prefer to make this fairly fast, although this is not our highest priority
"""
import mmap
import struct
import lzma
import sys

# Whether the program checks the integrity of data fields
CHECK_HASHES = True

try:
    from serpend.lookup3 import hash64
except ImportError:
    print("[!] Couldn't load the lookup3 hashing (maybe not built) disabling hash checks", file=sys.stderr)
    CHECK_HASHES = False


class SyslogParseException(Exception):
    """
    A custom error for the Syslog interpreting class
    """
    pass


class Syslog:
    def __init__(self, path):
        self.path = path
        self.area = self.handle = None
        self.__enter__()

    def close(self):
        if self.handle is not None and self.area is not None:
            self.handle.close()
            self.area.close()
            self.handle = self.area = None

    # with-Semantics
    def __enter__(self):
        # if already open
        if self.area is not None:
            return self

        self.handle = open(self.path, 'rb')
        self.area = mmap.mmap(self.handle.fileno(), 0, access=mmap.ACCESS_READ)

        # File should start with LPKSHHRH
        if self.area[:8] != b'LPKSHHRH':
            raise SyslogParseException("File signature did not match")
        return self

    def __exit__(self, type, value, traceback):
        self.close()
        return self

    def _data_from_offset(self, offset, dhash=None):
        """
        DataObject
        offset  0. uint8_t type;
        offset  1. uint8_t flags;
        offset  2. uint8_t reserved[6];
        offset  8. le64_t size;
        offset 16. le64_t hash;
        offset 24. le64_t next_hash_offset;
        offset 32. le64_t next_field_offset;
        offset 40. le64_t entry_offset; /* the first array entry we store inline */
        offset 48. le64_t entry_array_offset;
        offset 56. le64_t n_entries;

        Followed by a string '<key>=<value>' at offset 64 (maybe LZMA XZ / LZ4 encoded)
        """
        size, = struct.unpack_from("<Q", self.area, offset + 8)
        data_size = size - 64
        data = self.area[offset + 64:offset + 64 + data_size]

        if CHECK_HASHES:
            if dhash != hash64(data):
                print("[!] Possibly corrupted field encountered", file=sys.stderr)

        flags = self.area[offset + 1]

        # According to journal-def these are the options
        OBJECT_COMPRESSED_XZ = 1 << 0
        OBJECT_COMPRESSED_LZ4 = 1 << 1

        if flags & OBJECT_COMPRESSED_XZ:
            data = lzma.decompress(data)
        elif flags & OBJECT_COMPRESSED_LZ4:
            # should look like this when implemented:
            # data = lz4.decompress(data)
            # data should be a bytearray
            raise NotImplementedError("LZ4 encoding was not implemented yet")

        data = "".join(map(chr, data)).split("=", 1)
        if (len(data) != 2):
            raise SyslogParseException(
                "DataObject should've contained a key and value, however splitting it went wrong")
        return data

    def _entry_from_offset(self, offset):
        """
        EntryObject:
        offset  0. uint8_t type;
        offset  1. uint8_t flags;
        offset  2. uint8_t reserved[6];
        offset  8. le64_t size;
        offset 16. le64_t seqnum;
        offset 24. le64_t realtime;
        offset 32. le64_t monotonic;
        offset 40. sd_id128_t boot_id;
        offset 56. le64_t xor_hash;

        offset 64. Array of EntryItem
        le64_t object_offset;
        le64_t hash;
        """
        entry = {}

        size, seqnum, realtime, monotonic = struct.unpack_from("<4Q", self.area, offset + 8)
        entry['SEQNUM'] = "%d" % seqnum

        # Times are expressed in usec
        entry['__REALTIME_TIMESTAMP'] =  ('%.6f' % (realtime / 1000000)).ljust(10)
        entry['__MONOTONIC_TIMESTAMP'] = ('%.6f' % (monotonic / 1000000)).ljust(10)

        for entry_item_offset in range(offset + 64, offset + size, 16):
            data_offset, data_hash = struct.unpack_from("<2Q", self.area, entry_item_offset)
            data_key, data_value = self._data_from_offset(data_offset, dhash=data_hash)
            entry[data_key] = data_value

        return entry

    def _entry_offsets(self, entry_array_offset, recursive=True):
        """
        meant as a private method, parses an entry_array offset to a number of
        entry offsets. Note that this is done recursively by default, as the
        EntryArray object is internally linked to the offset of the next EntryArray.

        :param entry_array_offset an offset to an EntryArray Object
        :param recursive whether the linked structure of EntryArray Objects is followed

        offset  0. uint8_t type;
        offset  1. uint8_t flags;
        offset  2. uint8_t reserved[6];
        offset  8. le64_t size;
        offset 16. le64_t next_entry_array_offset;
        offset 24. le64_t items[];
        """

        # if entry_array_offset == 0, we're at the end
        while entry_array_offset != 0:
            # get the size attribute (little endian, 64bit) at 8 internal offset
            size, = struct.unpack_from("<Q", self.area, entry_array_offset + 8)

            # There are size (- header size (24 bytes)) / 8 entries
            for i in range((size - 24) // 8):
                entry_offset, = struct.unpack_from("<Q", self.area, entry_array_offset + 24 + i * 8)

                if entry_offset != 0:
                    yield entry_offset

            if recursive:
                entry_array_offset, = struct.unpack_from("<Q", self.area, entry_array_offset + 16)
            else:
                entry_array_offset = 0
        return
        yield

    def entries(self):
        """
        Returns a generator filled with entries.

        Entries are sure to have
        - A datetime 'REALTIME'
        - A datetime 'MONOTONIC'
        - A sequence number

        Entries probably all have a message 'MESSAGE'
        """

        """
        Parsing:
        Internally, we need to parse the file header. in __enter__ we already look at the signature

        File header

        offset   0     uint8_t signature[8]; /* "LPKSHHRH" */
        offset   8      le32_t compatible_flags;
        offset  12      le32_t incompatible_flags;
        offset  16     uint8_t state;
        offset  17     uint8_t reserved[7];
        offset  24  sd_id128_t file_id;
        offset  40  sd_id128_t machine_id;
        offset  56  sd_id128_t boot_id;    /* last writer */
        offset  72  sd_id128_t seqnum_id;
        offset  88      le64_t header_size;
        offset  96      le64_t arena_size;
        offset 104      le64_t data_hash_table_offset;
        offset 112      le64_t data_hash_table_size;
        offset 120      le64_t field_hash_table_offset;
        offset 128      le64_t field_hash_table_size;
        offset 136      le64_t tail_object_offset;
        offset 144      le64_t n_objects;
        offset 152      le64_t n_entries;
        offset 160      le64_t tail_entry_seqnum;
        offset 168      le64_t head_entry_seqnum;
        offset 176      le64_t entry_array_offset;
        offset 184      le64_t head_entry_realtime;
        offset 192      le64_t tail_entry_realtime;
        offset 200      le64_t tail_entry_monotonic;
        """

        entry_array_offset_offset = 176  # see table above
        initial_entry_array_offset, = struct.unpack_from("<Q", self.area, entry_array_offset_offset)

        for entry_offset in self._entry_offsets(initial_entry_array_offset):
            yield self._entry_from_offset(entry_offset)
        return
        yield

if __name__ == '__main__':
    logfile = '/run/log/journal/466e2282695544fcbdbebd6b989fe556/system.journal'

    f = Syslog(logfile)

    for entry in f.entries():
        print(entry)
        break

    f.close()
