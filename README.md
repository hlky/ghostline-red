# ghostline-red

Fast native tooling for Cyberpunk 2077 `.archive` containers and CR2W
resources. It provides focused command-line workflows for packing, extracting,
listing, inspecting, serializing, and deserializing game resources without
reimplementing WolvenKit's editors.

The project is currently tested most heavily on Windows. Packing works without
a DLL and falls back to uncompressed archive segments. The clean-room Kraken
backend encodes raw blocks, compressed constant blocks, and deterministic
recent-offset LZ streams for period-8 data. It also emits native-compatible
Huffman chunks for contiguous alphabets of 2–5, 8, or 16 symbols. Its decoder
additionally handles
stored inner chunks, stored byte
arrays, RLE byte arrays, simple recursive array composition, and LZ streams
with recent or explicitly coded legacy distances across both 128 KiB inner
chunks. Scaled offsets and their low-digit streams are also supported.
The decoder also supports the fully recovered old-table two-, three-, and
four-symbol forms of type-2 Huffman arrays, plus contiguous uniform 5-, 8-, and
16-symbol new-table forms. Both one-partition (type 2) and two-partition
(type 4) Huffman framing are supported for those tables. Other Huffman tables,
tANS, or multi-array composition still require a compatible `kraken.dll`,
which is not distributed with this repository.

## Features

- Pack loose depot trees into game- and WolvenKit-compatible archives.
- Extract archives with embedded plain or Kraken-compressed LXRS paths.
- List archive indexes without decompressing every payload.
- Inspect CR2W headers and table descriptors.
- Generate RED reflection metadata from a WolvenKit source checkout.
- Convert reflected CR2W resources to and from WKit-shaped JSON.
- Decode and rebuild typed RedPackage buffers.
- Grow CName/import tables and template-backed handle export arrays.
- Isolate native Kraken work in short-lived worker processes.
- Validate every compressed payload immediately by decompression.
- Encode and decode the implemented Kraken subset without a native library.

## Build

Install a current stable Rust toolchain, then run:

```powershell
git clone https://github.com/hlky/ghostline-red.git
cd ghostline-red
cargo build --release
```

The resulting executable is
`target\release\ghostline-red.exe` on Windows.

For compressed archives, pass the DLL explicitly or place it in the working
directory as `kraken.dll`:

```powershell
$red = '.\target\release\ghostline-red.exe'
$kraken = 'C:\Tools\WolvenKit\kraken.dll'
```

The `--kraken` argument is optional when packing. If the DLL is absent,
payloads that the clean-room encoder cannot make smaller are stored as ordinary
uncompressed archive segments.

## Clean-room Kraken commands

Encode a compatible stream without a DLL:

```powershell
& $red kraken-encode '.\input.bin' '.\input.kraken'
```

Decode a stream composed of currently supported block, entropy-array, and
chunk forms:

```powershell
& $red kraken-decode '.\input.kraken' '.\roundtrip.bin' --size 1048576
```

The exact decoded size is required because raw Kraken block framing does not
store it. Unknown entropy-compressed quantum forms fail closed with an explicit
error; they are not guessed or partially decoded.

## Archive commands

Pack a loose depot tree:

```powershell
& $red --kraken $kraken pack '.\source\archive' -o '.\build'
```

If the source directory is named `archive`, this writes
`.\build\archive.archive`.

Extract an archive:

```powershell
& $red --kraken $kraken extract `
  '.\build\archive.archive' `
  -o '.\build\extracted'
```

List its index:

```powershell
& $red archive-list '.\build\archive.archive'
& $red archive-list '.\build\archive.archive' --json
```

`--paths-root` resolves otherwise hash-only entries from a loose depot tree:

```powershell
& $red archive-list `
  'C:\Games\Cyberpunk 2077\archive\pc\content' `
  --paths-root '.\source\archive'
```

## CR2W commands

Generate the reflection schema from a WolvenKit source checkout:

```powershell
& $red schema-generate '.\WolvenKit' '.\red-schema.json'
```

Inspect a CR2W resource:

```powershell
& $red cr2w-inspect '.\example.questphase'
& $red cr2w-inspect '.\example.questphase' --json
```

Serialize binary CR2W to recursive WKit-shaped JSON:

```powershell
& $red --kraken $kraken cr2w-serialize `
  '.\example.questphase' `
  '.\example.questphase.json' `
  --schema '.\red-schema.json'
```

Deserialize JSON using an existing same-kind CR2W resource as its audited
layout template:

```powershell
& $red --kraken $kraken cr2w-deserialize `
  '.\example.questphase.json' `
  '.\rebuilt.questphase' `
  --template '.\example.questphase' `
  --schema '.\red-schema.json'
```

The template supplies the CR2W tables and layouts. Reflected values, shifted
offsets, table checksums, typed package buffers, and supported custom
appendices are rebuilt from the JSON.

Supported structural edits include changed strings and arrays, new CName and
depot-import entries, typed world-node data, typed RedPackage values, and new
exports when growing a non-empty handle array whose class already has a
template instance. Entirely novel RED classes and RedPackage chunk-topology
changes remain template-bound.

## LXRS metadata

WolvenKit archives may store depot paths in an extended block:

```text
magic             0x4C585253
version           1
uncompressedSize  u32
compressedSize    u32
pathCount         u32
payload           Kraken stream of NUL-terminated depot paths
```

Names absent from LXRS remain authoritative 64-bit depot-path hashes.
`--paths-root` supplies additional deterministic path candidates without
requiring WolvenKit's global hash database.

## Native Kraken safety

The native path uses:

- WolvenKit-compatible worst-case output capacity calculation;
- checked FFI boundaries and exact returned lengths;
- immediate compress/decompress byte validation;
- bounded parallel worker batches;
- process isolation so a bad DLL or native heap failure cannot corrupt the
  parent packer;
- uncompressed segment fallback when compression fails validation.

Set `KRAKEN_DLL` when running the optional native compression test:

```powershell
$env:KRAKEN_DLL = 'C:\Tools\WolvenKit\kraken.dll'
cargo test --all-features
```

## Validation and performance

The implementation was originally validated against:

- 80 authored CR2W resources with byte-identical binary → JSON → binary
  round trips;
- eight typed RedPackage-bearing resources;
- a 301-file archive with byte-identical pack/extract payloads;
- independent extraction and serialization by WolvenKit 8.17.4;
- a base-game `03_night_city.streamingworld` fixture.

Representative warm command-line measurements from the development machine:

| Workflow | ghostline-red | WolvenKit 8.17.4 |
|---|---:|---:|
| Questphase serialize | 89.7 ms | 17.01 s |
| Questphase deserialize | 89.7 ms | 16.92 s |
| Streamingworld serialize | 85.5 ms | 18.69 s |
| Streamingworld deserialize | 81.2 ms | 17.81 s |
| 301-file archive pack | 2.72 s | 9.71 s |
| 301-file archive extract | 0.52 s | 8.30 s |

These figures include process startup and describe one machine and fixture
set; they are not universal guarantees.

## Development

Run the standard checks before submitting changes:

```powershell
cargo fmt --all --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --all-features
```

The project is licensed under the [MIT License](LICENSE).
