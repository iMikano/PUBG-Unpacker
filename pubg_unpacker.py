#!/usr/bin/env python3
"""
PUBG Mobile PAK Unpacker
Extract files from PUBG Mobile PAK archives

Usage:
    python pubg_unpacker.py <input.pak> [output_dir]
"""

import itertools as it
import math
import struct
import zlib
import sys
import os
from pathlib import Path, PurePath
from functools import lru_cache

try:
    import gmalg
    from Crypto.Cipher import AES
    from Crypto.Hash import SHA1
    from Crypto.Util.Padding import unpad
    from zstandard import ZstdDecompressor, ZstdCompressionDict, DICT_TYPE_AUTO
except ImportError as e:
    print(f"[!] Missing required library: {e}")
    print("\nInstall dependencies:")
    print("    pip install pycryptodome zstandard gmalg")
    sys.exit(1)


# Constants
ZUC_KEY = bytes.fromhex('01010101010101010101010101010101')
ZUC_IV = bytes.fromhex('FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF')
RSA_MOD_1 = bytes.fromhex(
    'CBE8B9F2504050EF9831B719E9A6249A6D238505ADE909BDE78C180DED6072A0C3347B8AF4780E1F212D952D82D4BF7F233C1ECA499E1F9D9A85B4FAD759F54BABC1666C5DE411EA9E4B2374425DD6C6F54333BBC8F2610FE6063E4D0D6C21A671A8F7C3740555E5DC06D4E1691C456DB4116C0C012BF7B206E8311AAAEC689952BF804EF638F09D5822B4117B114208F14DEB459E80CB770E5B0D7978E21F5E6CED4999D3583108221A7AB28B960277ADB5690A332784019D9C195BE4EA9EA0A09459010F236465DE0D59C3EF7324E954E1118D93EE19F299760C2CDB963CE87973EA5ECC9BBE81C27D4C7C8572AC07E9BCEAC9BD72AB7A56A3C0AD736ABCE4')
RSA_MOD_2 = bytes.fromhex(
    '7F58E8A39A4DA4E87357DDD650EAA16D3B5CE95B213D1030A662566444796A78A84AE9AC3DBFFDE7F41094896696835DAF13B89E6EC2B84963B1B1BAF7151DA245C3FBFAE2A6AE18B2684D03F9229DE2C91440F2A3A3BCDE1E5680C16722A88039C73560D5D43F4B6562C2EEA5B1D926D86B51108A2643C70FB74D6442CE3A08339B8FD8F660AE88129B7AB8C46F2FA58124485CCCB1E987B05A6DA65A01858ED3F89905449AE42BB07290FCB9994BF22E26610BCABB9804783A3B9587917F3D97316EDDA15C5E13F79066407B55A93B291B68A4AC42A98D6E35FED84B14A792D154E62028DDAD20FC301951E5924BE9AD62FB719DD94CC30CAB871BEC4377A8')

SIMPLE1_KEY = 0x79
SIMPLE2_KEY = bytes.fromhex('E55B4ED1')
SIMPLE2_BLOCK_SIZE = 16

SM4_SECRET_2 = 'Q0hVTKey$as*1ZFlQCiA'
SM4_SECRET_4 = 'eb691efea914241317a8'

# Update when game updates
SM4_SECRET_NEW = [
    'xG2qW5lP7lV2iN5fN5pG',
    'xT1cJ6dL5wC0kK1rB4dK',
    'qC4jS5bZ6fL5xE6nD4zA',
    'gD4jQ2aL3bS3lC3xT0iW',
    'xU1yQ8wE9zY3gZ3bT5aE',
]
EM_SIMPLE1 = 1
EM_SIMPLE2 = 16
EM_SM4_2 = 2
EM_SM4_4 = 4
EM_SM4_NEW_BASE = 31
EM_SM4_NEW_MASK = ~EM_SM4_NEW_BASE

CM_NONE = 0
CM_ZLIB = 1
CM_ZSTD = 6
CM_ZSTD_DICT = 8
CM_MASK = 15


class SM4:
    """Tencent custom SM4 cipher"""
    SBOX = [
        0x34, 0x66, 0x25, 0x74, 0x89, 0x78, 0xE4, 0xA9, 0x5A, 0x41, 0xBC, 0x7A, 0xD6, 0x16, 0x21, 0x23,
        0x4D, 0x61, 0xDA, 0x94, 0x9B, 0xDF, 0x13, 0x3C, 0x69, 0x3A, 0x31, 0x0A, 0x5F, 0xD7, 0x99, 0x95,
        0xF1, 0xAE, 0x72, 0x3D, 0x07, 0x60, 0x24, 0xB6, 0x98, 0xEE, 0xC4, 0xA2, 0x2D, 0x88, 0xDD, 0x8D,
        0x04, 0xEA, 0xBB, 0x11, 0xCA, 0x3E, 0x5D, 0xA1, 0xF6, 0x3F, 0xB0, 0x97, 0x80, 0x47, 0x2B, 0xA6,
        0xE6, 0xF7, 0xD9, 0xB1, 0x59, 0xC0, 0x7C, 0xBE, 0x54, 0x28, 0xB7, 0x7E, 0x4F, 0xF8, 0x43, 0x6E,
        0xA0, 0x50, 0x0E, 0xF5, 0x90, 0xB8, 0xFB, 0xA3, 0x7B, 0x62, 0x19, 0x46, 0x03, 0x2A, 0xB9, 0x8F,
        0x9F, 0x77, 0xB4, 0x5B, 0x83, 0x87, 0x08, 0xEB, 0xE2, 0x1E, 0x42, 0xF0, 0x0F, 0xE8, 0x71, 0x6A,
        0x75, 0xAD, 0x55, 0x1F, 0xB5, 0xAB, 0x33, 0xFA, 0x7F, 0x15, 0xBD, 0x85, 0xD8, 0x06, 0x68, 0xB3,
        0x52, 0x30, 0x48, 0x0B, 0x00, 0xED, 0xEF, 0xB2, 0x57, 0x8E, 0xE7, 0x6C, 0xD5, 0xE5, 0x2E, 0x53,
        0x82, 0x05, 0xF9, 0x81, 0xF4, 0x56, 0xBF, 0x8C, 0x4B, 0xE3, 0xDB, 0x4A, 0x91, 0x4C, 0x2C, 0xD3,
        0x40, 0x29, 0x4E, 0x20, 0x14, 0x36, 0x79, 0x09, 0x6F, 0xD1, 0x37, 0xE0, 0x39, 0x0C, 0x8A, 0x92,
        0x38, 0x12, 0x35, 0x6D, 0xE1, 0xFD, 0x93, 0x9A, 0x17, 0xD4, 0xC9, 0x9C, 0x6B, 0x84, 0x26, 0x9D,
        0xAF, 0x76, 0xC1, 0x9E, 0xD0, 0x96, 0xC5, 0xCB, 0xE9, 0x73, 0x49, 0xD2, 0xCD, 0x64, 0xC3, 0xC7,
        0x01, 0x7D, 0xF3, 0xAC, 0xFC, 0xDE, 0xA4, 0x44, 0x32, 0x1B, 0xC2, 0xBA, 0x1C, 0x02, 0xC6, 0x27,
        0x45, 0x8B, 0xF2, 0x18, 0xA7, 0x10, 0x51, 0x1D, 0xC8, 0xCF, 0x63, 0xFF, 0x2F, 0x0D, 0x58, 0xCE,
        0x65, 0xA5, 0xDC, 0x1A, 0x3B, 0x86, 0xFE, 0x22, 0x5C, 0xA8, 0x5E, 0x67, 0xAA, 0xEC, 0x70, 0xCC
    ]

    FK = [0x46970E9C, 0x4BC0685E, 0x59056186, 0xBCA2491E]
    CK = [
        0x000EB92B, 0x3A0AE783, 0x9E3B5C67, 0xADDBDABF, 0x7B7484CB, 0x49156C63, 0xC79AB5E7, 0x79EC9CFF,
        0x1725BEAB, 0x2FB89CA3, 0x24808AD7, 0xDDD28B1F, 0x4740DA4B, 0xBBC3EA73, 0x247B30E7, 0x91BE385F,
        0x0401248B, 0x45FCD3A3, 0x530B4CE7, 0xC68DD35F, 0xE3D16C2B, 0x4F698C13, 0x6B92C747, 0x769EFB1F,
        0x4C73BE9B, 0xC942B193, 0xAD80D827, 0x372FB33F, 0x13CB6AAB, 0x2BDC0AA3, 0x17A4A247, 0xD5E96CAF
    ]

    def __init__(self, key: bytes):
        assert len(key) == 16
        self.rk = self._expand_key(key)

    @staticmethod
    def key_length():
        return 16

    @staticmethod
    def block_length():
        return 16

    def _expand_key(self, key: bytes):
        k = struct.unpack('>4I', key)
        mk = [k[i] ^ SM4.FK[i] for i in range(4)]
        rk = []
        for i in range(32):
            rk.append(mk[0] ^ self._t_key(mk[1] ^ mk[2] ^ mk[3] ^ SM4.CK[i]))
            mk = mk[1:] + [rk[-1]]
        return rk

    def _t_key(self, x):
        return self._l_key(self._tau(x))

    @staticmethod
    def _l_key(x):
        return x ^ ((x << 13) | (x >> 19)) ^ ((x << 23) | (x >> 9))

    def _tau(self, x):
        b = [(x >> (24 - 8 * i)) & 0xFF for i in range(4)]
        b = [SM4.SBOX[b[i]] for i in range(4)]
        return (b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]

    def _l(self, x):
        # Mask to 32 bits to prevent overflow
        x = x & 0xFFFFFFFF
        result = x ^ ((x << 2) | (x >> 30)) ^ ((x << 10) | (x >> 22)) ^ ((x << 18) | (x >> 14)) ^ ((x << 24) | (x >> 8))
        return result & 0xFFFFFFFF

    def _t(self, x):
        return self._l(self._tau(x))

    def _f(self, x0, x1, x2, x3, rk):
        return (x0 ^ self._t(x1 ^ x2 ^ x3 ^ rk)) & 0xFFFFFFFF

    def _crypt_block(self, block: bytes, rk):
        x = list(struct.unpack('>4I', block))
        for i in range(32):
            x.append(self._f(x[i], x[i+1], x[i+2], x[i+3], rk[i]))
        return struct.pack('>4I', x[35], x[34], x[33], x[32])

    def decrypt(self, ciphertext: bytes) -> bytes:
        assert len(ciphertext) == 16
        return self._crypt_block(ciphertext, self.rk[::-1])


class Reader:
    """Binary reader"""

    def __init__(self, buffer, cursor=0):
        self._buffer = buffer
        self._cursor = cursor

    def u1(self, move=True):
        return self.unpack('B', move=move)[0]

    def u4(self, move=True):
        return self.unpack('<I', move=move)[0]

    def u8(self, move=True):
        return self.unpack('<Q', move=move)[0]

    def i4(self, move=True):
        return self.unpack('<i', move=move)[0]

    def s(self, n: int, move=True):
        return self.unpack(f'{n}s', move=move)[0]

    def unpack(self, fmt: str, offset=0, move=True):
        x = struct.unpack_from(fmt, self._buffer, self._cursor + offset)
        if move:
            self._cursor += struct.calcsize(fmt)
        return x

    def string(self, move=True):
        length = self.i4(move=move)
        if length == 0:
            return str()
        assert length > 0
        offset = 0 if move else 4
        return self.unpack(f'{length}s', offset=offset, move=move)[0].rstrip(b'\x00').decode()


class Crypto:
    """Encryption/decryption methods"""

    @staticmethod
    def zuc_keystream():
        zuc = gmalg.ZUC(ZUC_KEY, ZUC_IV)
        return [struct.unpack('>I', zuc.generate())[0] for _ in range(16)]

    @staticmethod
    def rsa_extract(signature: bytes, modulus: bytes) -> bytes:
        c = int.from_bytes(signature, 'little')
        n = int.from_bytes(modulus, 'little')
        e = 0x10001
        m = pow(c, e, n).to_bytes(256, 'little').rstrip(b'\x00')

        padding = (4 - len(m) % 4) % 4
        m = m + b'\x00' * padding

        if len(m) < 43:
            return bytes()

        x1 = m[1:21]
        x2 = m[21:]
        x1 = bytes(a ^ b for a, b in zip(x1, Crypto._hash_expand(x2, 20)))
        x2 = bytes(a ^ b for a, b in zip(x2, Crypto._hash_expand(x1, len(x2))))

        if x2[:20] != SHA1.new(b'\x00' * 20).digest():
            return bytes()

        skip = 1 + next((i for i in range(20, len(x2)) if x2[i] != 0), len(x2) - 20)
        return x2[skip:]

    @staticmethod
    def _hash_expand(data: bytes, length: int) -> bytes:
        result = b''
        for _ in range(math.ceil(length / 20)):
            result += SHA1.new(data).digest()
        return result[:length]

    @staticmethod
    def decrypt_index(ciphertext: bytes, pak_info) -> bytes:
        if pak_info.version > 7:
            key = Crypto.rsa_extract(pak_info.packed_key, RSA_MOD_1)
            iv = Crypto.rsa_extract(pak_info.packed_iv, RSA_MOD_1)
            assert len(key) == 32 and len(iv) == 32
            aes = AES.new(key, AES.MODE_CBC, iv[:16])
            return unpad(aes.decrypt(ciphertext), AES.block_size)
        else:
            return bytes(x ^ SIMPLE1_KEY for x in ciphertext)

    @staticmethod
    @lru_cache(maxsize=100)
    def derive_sm4_key(filename_stem: str, encryption_method: int) -> bytes:
        stem = filename_stem.lower()

        if encryption_method == EM_SM4_2:
            secret = SM4_SECRET_2
        elif encryption_method == EM_SM4_4:
            secret = SM4_SECRET_4
        else:
            index = (encryption_method - EM_SM4_NEW_BASE) % len(SM4_SECRET_NEW)
            secret = f'{SM4_SECRET_NEW[index]}{encryption_method}'

        combined = str(stem + secret)
        return SHA1.new(combined.encode()).digest()[:16]

    @staticmethod
    @lru_cache(maxsize=100)
    def get_sm4(key: bytes) -> SM4:
        return SM4(key)

    @staticmethod
    def decrypt_block(ciphertext: bytes, filename_stem: str, encryption_method: int) -> bytes:
        if encryption_method == EM_SIMPLE1:
            return bytes(x ^ SIMPLE1_KEY for x in ciphertext)
        elif encryption_method == EM_SIMPLE2:
            assert len(ciphertext) % 16 == 0
            key = struct.unpack('<I', SIMPLE2_KEY)[0]
            result = []
            for x in struct.unpack(f'<{len(ciphertext)//4}I', ciphertext):
                key ^= x
                result.append(struct.pack('<I', key))
            return b''.join(result)
        elif encryption_method in (EM_SM4_2, EM_SM4_4) or encryption_method & EM_SM4_NEW_MASK:
            assert len(ciphertext) % 16 == 0
            sm4_key = Crypto.derive_sm4_key(filename_stem, encryption_method)
            sm4 = Crypto.get_sm4(sm4_key)
            return b''.join(sm4.decrypt(ciphertext[i:i+16]) for i in range(0, len(ciphertext), 16))
        else:
            raise ValueError(f"Unknown encryption method: {encryption_method}")


class Compression:
    """Decompression methods"""

    @staticmethod
    @lru_cache(maxsize=10)
    def get_zstd_decompressor(dict_data):
        if dict_data:
            return ZstdDecompressor(ZstdCompressionDict(dict_data, DICT_TYPE_AUTO))
        return ZstdDecompressor()

    @staticmethod
    def decompress(data: bytes, method: int, zstd_dict=None) -> bytes:
        if method == CM_ZLIB:
            return zlib.decompress(data)
        elif method == CM_ZSTD or method == CM_ZSTD_DICT:
            decompressor = Compression.get_zstd_decompressor(zstd_dict if method == CM_ZSTD_DICT else None)
            return decompressor.decompress(data)
        else:
            raise ValueError(f"Unknown compression method: {method}")


class PakInfo:
    """PAK footer"""

    @staticmethod
    def calculate_footer_size(version: int) -> int:
        size = 1 + 4 + 4 + 20 + 8 + 8
        if version >= 7:
            size += 32
        if version >= 8:
            size += 768
        if version >= 9:
            size += 8
        if version >= 12:
            size += 20
        return size

    def __init__(self, buffer: bytes, keystream: list):
        base_footer = bytes(buffer[-45:])
        base_reader = Reader(base_footer)
        temp_encrypted = ((base_reader.u1() ^ keystream[3]) & 0xFF) == 1
        temp_magic = base_reader.u4() ^ keystream[2]
        temp_version = base_reader.u4()

        self.index_encrypted = temp_encrypted
        self.magic = temp_magic
        self.version = temp_version

        extended_size = self.calculate_footer_size(self.version) - 45
        if extended_size > 0:
            extended_footer = bytes(buffer[-(45 + extended_size):-45])
            ext_reader = Reader(extended_footer)

            if self.version >= 7:
                unk_enc = ext_reader.s(32)
                key = struct.pack('<8I', *keystream[7:15])
                self.unk1 = bytes(a ^ b for a, b in zip(unk_enc, key))
            else:
                self.unk1 = b''

            if self.version >= 8:
                self.packed_key = ext_reader.s(256)
                self.packed_iv = ext_reader.s(256)
                self.packed_index_hash = ext_reader.s(256)
            else:
                self.packed_key = self.packed_iv = self.packed_index_hash = b''

            if self.version >= 9:
                self.stem_hash = ext_reader.u4() ^ keystream[8]
                self.unk2 = ext_reader.u4() ^ keystream[9]
            else:
                self.stem_hash = self.unk2 = 0

            if self.version >= 12:
                self.content_hash = ext_reader.s(20)
            else:
                self.content_hash = b''
        else:
            self.unk1 = b''
            self.packed_key = self.packed_iv = self.packed_index_hash = b''
            self.stem_hash = self.unk2 = 0
            self.content_hash = b''

        if self.version >= 6:
            index_hash_enc = base_reader.s(20)
            key = struct.pack('<5I', *keystream[4:9])
            self.index_hash = bytes(a ^ b for a, b in zip(index_hash_enc, key))
        else:
            self.index_hash = b''

        self.index_size = base_reader.u8() ^ ((keystream[10] << 32) | keystream[11])
        self.index_offset = base_reader.u8() ^ ((keystream[0] << 32) | keystream[1])

        if self.version <= 3:
            self.index_encrypted = False


class PakEntry:
    """PAK entry"""

    def __init__(self, reader: Reader, version: int):
        self.content_hash = reader.s(20)
        if version <= 1:
            _ = reader.u8()
        self.offset = reader.u8()
        self.uncompressed_size = reader.u8()
        self.compression_method = reader.u4() & CM_MASK
        self.size = reader.u8()
        self.unk1 = reader.u1() if version >= 5 else 0
        self.unk2 = reader.s(20) if version >= 5 else b''

        if self.compression_method != 0 and version >= 3:
            block_count = reader.u4()
            self.blocks = [(reader.u8(), reader.u8()) for _ in range(block_count)]
        else:
            self.blocks = []

        self.block_size = reader.u4() if version >= 4 else 0
        self.encrypted = reader.u1() == 1 if version >= 4 else False
        self.encryption_method = reader.u4() if version >= 12 else 0
        self.index_new_sep = reader.u4() if version >= 12 else 0


class PubgPakFile:
    """PAK unpacker"""

    def __init__(self, pak_path: Path):
        self.pak_path = Path(pak_path)
        print(f"[*] Opening {self.pak_path.name}")

        with open(pak_path, 'rb') as f:
            self.data = memoryview(f.read())

        self.zstd_dict = None
        self.files = []
        self.index = {}

        keystream = Crypto.zuc_keystream()
        self.info = PakInfo(self.data, keystream)

        print(f"[*] PAK Version: {self.info.version}")
        print(f"[*] Index encrypted: {self.info.index_encrypted}")
        print(f"[*] Magic: 0x{self.info.magic:08X}")

        if self.info.magic != 0x5A6F12E1:
            print(f"[!] Warning: Non-standard magic number (expected 0x5A6F12E1, got 0x{self.info.magic:08X})")

        if self.info.version >= 9:
            expected = zlib.crc32(self.pak_path.stem.encode('utf-32le'))
            if self.info.stem_hash != expected:
                print(f"[!] Warning: Filename hash mismatch")

        self._load_index()

    def _load_index(self):
        index_data = self.data[self.info.index_offset:][:self.info.index_size]

        if self.info.index_encrypted:
            print("[*] Decrypting index...")
            index_data = Crypto.decrypt_index(bytes(index_data), self.info)

        if self.info.version >= 8:
            expected = Crypto.rsa_extract(self.info.packed_index_hash, RSA_MOD_2)
        else:
            expected = self.info.index_hash

        actual = SHA1.new(index_data).digest()
        if expected and expected != actual:
            raise ValueError("Index hash mismatch")

        reader = Reader(index_data)
        mount_point = reader.string()
        print(f"[*] Mount point: {mount_point}")

        file_count = reader.u4()
        self.files = [PakEntry(reader, self.info.version) for _ in range(file_count)]

        dir_count = reader.u8()
        for _ in range(dir_count):
            dir_path = PurePath(reader.string())
            file_count = reader.u8()
            entries = {}
            for _ in range(file_count):
                filename = reader.string()
                file_idx = ~reader.i4()
                entries[filename] = self.files[file_idx]

            if 'zstddic' in str(dir_path).lower():
                entry = list(entries.values())[0]
                if not entry.encrypted and entry.compression_method == CM_NONE:
                    self._load_zstd_dict(entry)
                    continue

            self.index[dir_path] = entries

        print(f"[+] Loaded {len(self.files)} files in {len(self.index)} directories")

    def _load_zstd_dict(self, entry: PakEntry):
        print("[*] Loading ZSTD dictionary...")
        data = self.data[entry.offset:][:entry.size]
        reader = Reader(data)
        dict_size = reader.u8()
        _ = reader.u4()
        assert dict_size == reader.u4()
        self.zstd_dict = reader.s(dict_size)

    def _extract_file(self, path: Path, entry: PakEntry):
        with open(path, 'wb') as f:
            if entry.compression_method == CM_NONE:
                size = entry.size
                if entry.encrypted and (entry.encryption_method == EM_SIMPLE2 or entry.encryption_method in (EM_SM4_2, EM_SM4_4) or entry.encryption_method & EM_SM4_NEW_MASK):
                    size = ((size + 15) // 16) * 16
                data = bytes(self.data[entry.offset:][:size])
                if entry.encrypted:
                    data = Crypto.decrypt_block(data, path.stem, entry.encryption_method)
                f.write(data[:entry.size])
            else:
                block_count = len(entry.blocks)
                if entry.encrypted and (entry.encryption_method in (EM_SM4_2, EM_SM4_4) or entry.encryption_method & EM_SM4_NEW_MASK):
                    indices = self._generate_permutation(block_count)
                else:
                    indices = list(range(block_count))

                for block_idx, idx in enumerate(indices):
                    start, end = entry.blocks[idx]
                    size = end - start
                    if entry.encrypted and (entry.encryption_method == EM_SIMPLE2 or entry.encryption_method in (EM_SM4_2, EM_SM4_4) or entry.encryption_method & EM_SM4_NEW_MASK):
                        size = ((size + 15) // 16) * 16
                    data = bytes(self.data[start:][:size])

                    if entry.encrypted:
                        data = Crypto.decrypt_block(data, path.stem, entry.encryption_method)

                    data = Compression.decompress(data, entry.compression_method, self.zstd_dict)
                    f.write(data)

    def _generate_permutation(self, n: int):
        if n <= 1:
            return list(range(n))

        def wrap(x: int) -> int:
            x &= 0xFFFFFFFF
            if not x & 0x80000000:
                return x
            else:
                return ((x + 0x80000000) & 0xFFFFFFFF) - 0x80000000

        state = n
        permutation = []
        while len(permutation) < n:
            x1 = wrap(0x41C64E6D * state)
            state = wrap(x1 + 12345)
            x2 = wrap(x1 + 0x13038) if state < 0 else state
            x = ((x2 >> 16) & 0xFFFFFFFF) % 0x7FFF
            idx = x % n
            if idx not in permutation:
                permutation.append(idx)

        inverse = [0] * n
        for i, x in enumerate(permutation):
            inverse[x] = i
        return inverse

    def extract(self, output_dir: Path):
        output_dir = Path(output_dir)
        print(f"\n[*] Extracting to: {output_dir}")

        total = sum(len(files) for files in self.index.values())
        count = 0

        for dir_path, files in self.index.items():
            out_path = output_dir / dir_path
            out_path.mkdir(parents=True, exist_ok=True)

            for filename, entry in files.items():
                file_path = out_path / filename
                try:
                    self._extract_file(file_path, entry)
                    count += 1
                    if count % 50 == 0:
                        print(f"[*] Progress: {count}/{total} files")
                except Exception as e:
                    print(f"[!] Failed to extract {file_path.name}: {e}")
                    count += 1

        print(f"\n[+] Extracted {count} files successfully!")


def main():
    if len(sys.argv) < 2:
        print("PUBG Mobile PAK Unpacker")
        print("\nUsage:")
        print(f"    {sys.argv[0]} <input.pak> [output_dir]")
        print("\nExample:")
        print(f"    {sys.argv[0]} core_patch_4.1.0.20530.pak extracted/")
        return 1

    pak_file = Path(sys.argv[1])
    output_dir = Path(sys.argv[2]) if len(sys.argv) > 2 else Path(pak_file.stem + "_extracted")

    if not pak_file.exists():
        print(f"[!] File not found: {pak_file}")
        return 1

    try:
        pak = PubgPakFile(pak_file)
        pak.extract(output_dir)
        print(f"\n[+] Done! Files extracted to: {output_dir}")
        return 0
    except Exception as e:
        print(f"\n[!] Error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
