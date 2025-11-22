# PUBG Mobile PAK Unpacker

Extract files from PUBG Mobile PAK archives for PUBG Mobile V4.1.0

## Features

- Extract both `game_patch` and `core_patch` PAK files
- Support for multiple encryption methods (SIMPLE1, SIMPLE2, SM4 variants)
- Handles ZUC footer encryption and AES index encryption
- Support for zlib, ZSTD, and ZSTD with dictionary compression
- Automatically decrypts and decompresses files

## Installation

```bash
pip install -r requirements.txt
```

Required libraries:
- `pycryptodome` - AES and SHA1
- `gmalg` - ZUC stream cipher
- `zstandard` - ZSTD decompression

## Usage

### Basic Usage

```bash
python pubg_unpacker.py <input.pak> [output_dir]
```

If no output directory is specified, files will be extracted to `<pakname>_extracted/`

## Supported Files

Works with both PAK types from PUBG Mobile:
- `game_patch_*.pak` - Main game assets
- `core_patch_*.pak` - Core game files

Tested with versions up to 4.1.0. Should work with newer versions unless Tencent changes the encryption.

## Technical Details

### PAK Format

- **Version**: Supports v1-14
- **Magic**: Standard (0x5A6F12E1) and custom variants (0x4C515443)
- **Block size**: 64KB (standard UE4)

### Encryption Methods

The unpacker handles multiple encryption methods:

**SIMPLE1** (method 1)
- XOR cipher with fixed key `0x79`
- Used for basic file obfuscation

**SIMPLE2** (method 16)
- Rolling XOR cipher with 16-byte blocks
- Key: `0xE55B4ED1`
- Requires proper alignment to 16-byte boundary

**SM4** (methods 2, 4, 31+)
- Tencent's custom SM4 variant
- Custom SBOX, FK, and CK constants
- Per-file key derivation: `SHA1(filename_stem + secret + method)[:16]`
- Block permutation using LCG for compressed files

### Footer Encryption

Footer uses ZUC stream cipher:
- Fixed key: `0x01010101...` (16 bytes)
- Fixed IV: `0xFFFFFFFF...` (16 bytes)
- Selective field encryption with 16-word keystream
- Only base footer (last 45 bytes) is fully encrypted

### Index Encryption

Index uses AES-256-CBC when encrypted:
- Key/IV extracted from RSA-padded footer signature
- SHA1 hash verification after decryption

### Compression

Three methods supported:
- **Zlib** (method 1): Standard deflate
- **ZSTD** (method 6): Zstandard
- **ZSTD with dict** (method 8): Uses embedded dictionary file

Files are split into 64KB blocks before compression.

## Troubleshooting

### "Missing required library" error
Install dependencies: `pip install -r requirements.txt`

### "Non-standard magic number" warning
This is normal for `core_patch` files. They use `0x4C515443` instead of the standard magic. Extraction will continue normally.

### "SIMPLE2 encrypted data size not aligned" warning
Some files have non-standard sizes. The unpacker handles this automatically.

### Files extract but are corrupted
- Check if you're using the correct PAK file (not partially downloaded)
- Verify the file isn't from a newer game version with changed encryption

## How It Works

1. **Read footer**: Parse ZUC-encrypted footer from end of file
2. **Decrypt index**: Use AES-256-CBC to decrypt file index (if encrypted)
3. **Parse entries**: Read file metadata (offset, size, compression, encryption)
4. **Extract files**: For each file:
   - Read compressed/encrypted blocks from PAK
   - Apply inverse LCG permutation (for SM4)
   - Decrypt blocks (SIMPLE/SM4)
   - Decompress (zlib/ZSTD)
   - Write to disk

## File Structure

Extracted files maintain the original directory structure:

```
extracted_folder/
├── Config/
│   └── DefaultEngineRedirects_BLUEHOLE.ini
├── Content/
│   ├── Paks/
│   ├── UI/
│   └── ...
└── ...
```

Mount point is typically `../../../ShadowTrackerExtra/` for core/game patches.

## License

Educational and research purposes only.
