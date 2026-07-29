# ghostline-red

Fast native tooling for Cyberpunk 2077 `.archive` containers and CR2W
resources. It provides focused command-line workflows for packing, extracting,
listing, inspecting, serializing, and deserializing game resources without
reimplementing WolvenKit's editors.

The project is currently tested most heavily on Windows. Normal pack, extract,
list, CR2W, and LXRS workflows do not require `kraken.dll`.

The clean-room Kraken decoder implements stored and compressed block framing,
both 128 KiB inner chunks, RLE, general old/new Huffman tables, one- and
two-partition Huffman streams, tANS, recursive and indexed multi-array
composition, both LZ modes, recent and explicit legacy distances, scaled
offsets, paired front/back suffix streams, and extended literal/match lengths.
Malformed streams fail closed with checked bounds and exact-consumption rules.

The encoder independently chooses among raw, memset, general canonical
Huffman, compact tANS, and greedy LZ representations. Its LZ matcher supports
multiple explicit distances, scaled offsets, three-entry move-to-front
recent-offset reuse, and extended lengths. An early stable-distance path keeps
periodic resources fast. Encoder representation choice is intentionally
smaller than the decoder grammar: indexed arrays and two-partition Huffman are
composition/framing alternatives, not requirements for producing compatible
streams.

## Preliminary performance

Whole-process measurements on an Intel Xeon E5-2686 v4, Windows, Rust 1.95.0
release build, using a cached 32 MiB corpus with a 97-byte pseudorandom period:

| Path | Warm throughput | Output size |
|---|---:|---:|
| Clean Rust encode | ~745 MiB/s | 31,872 bytes |
| Native encode through isolated worker | ~123 MiB/s | 9,103 bytes |
| Clean Rust decode | ~658 MiB/s | 32 MiB |

The fixed-width matcher, stable-distance path, and bulk overlap-copy pass
improved the same clean encode/decode measurements from approximately
345/221 MiB/s. These numbers
include process startup and cached file I/O and are intended as reproducible
workflow comparisons, not cycle-level codec microbenchmarks. Compression ratio
depends heavily on the corpus; the native encoder remains substantially
stronger on general data.

## Features

- Pack loose depot trees into game- and WolvenKit-compatible archives.
- Extract archives with embedded plain or Kraken-compressed LXRS paths.
- List archive indexes without decompressing every payload.
- Inspect CR2W headers and table descriptors.
- Generate RED reflection metadata from a WolvenKit source checkout.
- Convert reflected CR2W resources to and from WKit-shaped JSON.
- Export `.mesh` geometry to GLB with position, normal, tangent, color, UV,
  index, LOD, and appearance-material metadata.
- Export a selected mesh appearance's material sidecar, textures, multilayer
  setup/template JSON, and decoded multilayer masks directly from game
  archives.
- Decode and rebuild typed RedPackage buffers.
- Grow CName/import tables and template-backed handle export arrays.
- Isolate native Kraken work in short-lived worker processes.
- Validate every compressed payload immediately by decompression.
- Encode and decode Kraken streams without a native library.

## Build

Install a current stable Rust toolchain, then run:

```powershell
git clone https://github.com/hlky/ghostline-red.git
cd ghostline-red
cargo build --release
```

The resulting executable is
`target\release\ghostline-red.exe` on Windows.

No DLL is needed for normal use. To run optional native differential checks,
pass WolvenKit's library explicitly or place it in the working directory as
`kraken.dll`:

```powershell
$red = '.\target\release\ghostline-red.exe'
$kraken = 'C:\Tools\WolvenKit\kraken.dll'
```

The `--kraken` argument identifies the library only for explicit native
diagnostic flags. Normal archive, CR2W, and LXRS paths always use the Rust
implementation. Payloads that do not benefit from Rust compression are stored
as ordinary uncompressed archive segments.

## Clean-room Kraken commands

Encode a compatible stream without a DLL:

```powershell
& $red kraken-encode '.\input.bin' '.\input.kraken'
```

Add `--native` to use the selected library in the crash-isolated worker when
collecting differential compression vectors.

Decode a compatible Kraken stream:

```powershell
& $red kraken-decode '.\input.kraken' '.\roundtrip.bin' --size 1048576
```

For differential diagnosis only, decoding can fall back to a native library
inside the crash-isolated worker:

```powershell
& $red --kraken $kraken kraken-decode `
  '.\input.kraken' '.\roundtrip.bin' --size 1048576 --native-fallback
```

The exact decoded size is required because raw Kraken block framing does not
store it. Malformed or unknown quantum forms fail closed with an explicit
error; they are not guessed or partially decoded.

## Archive commands

Pack a loose depot tree:

```powershell
& $red pack '.\source\archive' -o '.\build'
```

If the source directory is named `archive`, this writes
`.\build\archive.archive`.

Extract an archive:

```powershell
& $red extract `
  '.\build\archive.archive' `
  -o '.\build\extracted'
```

Extract one exact depot path from a stock or mod archive (equivalent to
`WolvenKit.CLI extract ... -w <path>`):

```powershell
& $red extract `
  'H:\Cyberpunk 2077\archive\pc\content\basegame_3_nightcity.archive' `
  -o '.\extracted' `
  -w 'base\worlds\03_night_city\_compiled\default\03_night_city.streamingworld'
```

Scoped extraction hashes the supplied path directly, so it does not need an
embedded LXRS path table or `--paths-root`.

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
& $red cr2w-serialize `
  '.\example.questphase' `
  '.\example.questphase.json' `
  --schema '.\red-schema.json'
```

For archive-backed staging, serialize many depot resources while opening the
game archive index only once. The manifest schema is:

```json
{
  "jobs": [
    {
      "resource": "base\\worlds\\03_night_city\\_compiled\\default\\example.streamingsector",
      "output": "C:\\world-cache\\example.streamingsector.json"
    }
  ]
}
```

Run it with:

```powershell
& $red cr2w-serialize-batch '.\serialize-jobs.json' `
  --schema '.\red-schema.json' `
  --archives-root 'H:\Cyberpunk 2077\archive\pc' `
  --report '.\serialize-report.json' `
  --threads 8
```

The exact CLI shape is
`cr2w-serialize-batch <MANIFEST> --schema <SCHEMA>... --archives-root
<ARCHIVES_ROOT> --report <REPORT> [--threads <THREADS>]`. Repeat `--schema`
to merge schema sources in increasing precedence order. `--threads 0` is the
default and uses every available logical CPU.

Every output is pretty JSON written through a temporary file in its destination
directory, then atomically replaced. Missing parent directories are created.
Jobs continue independently after errors, and the report preserves manifest
order:

```json
[
  {
    "resource": "base\\worlds\\03_night_city\\_compiled\\default\\example.streamingsector",
    "output": "C:\\world-cache\\example.streamingsector.json",
    "error": null
  }
]
```

Failed jobs contain their error chain in `error`; successful jobs contain
`null`. The command writes the complete report and exits nonzero when any job
fails.

Deserialize JSON using an existing same-kind CR2W resource as its audited
layout template:

```powershell
& $red cr2w-deserialize `
  '.\example.questphase.json' `
  '.\rebuilt.questphase' `
  --template '.\example.questphase' `
  --schema '.\red-schema.json'
```

The template supplies the CR2W tables and layouts. Reflected values, shifted
offsets, table checksums, typed package buffers, and supported custom
appendices are rebuilt from the JSON. Non-default fixed-size properties absent
from a template instance can be inserted when their RED type and ordinal are
available in the generated schema.

Supported structural edits include changed strings and arrays, new CName and
depot-import entries, typed world-node data, typed RedPackage values, and new
exports when growing a non-empty handle array whose class already has a
template instance. Exports disconnected from the authored JSON handle graph
are pruned, and retained handle, parent, and embedded-file indices are
compacted to match the rebuilt export table. Unreferenced imports are removed,
with resource and embedded-file import indices remapped to the compact table.
Entirely novel RED classes and RedPackage chunk-topology changes remain
template-bound.

## Mesh and material export

Export native GLB geometry only:

```powershell
& $red mesh-export '.\extracted\item.mesh' `
  --schema '.\red-schema.json' `
  --output '.\item.glb'
```

Add a Blender-compatible material sidecar and uncooked dependency repository:

```powershell
& $red mesh-export '.\extracted\item.mesh' `
  --schema '.\red-schema.json' `
  --output '.\item.glb' `
  --archives-root 'H:\Cyberpunk 2077\archive\pc' `
  --material-repo '.\material-repo' `
  --appearance 'denim_blue_red' `
  --pbr --pbr-size 512
```

`--appearance` limits work to the materials used by that appearance. The
repository is reusable: existing textures, mask lists, and recursive material
documents are treated as a shared dependency cache. `--pbr` resolves the
selected Cyberpunk materials into standard glTF base-color,
metallic-roughness, normal, emissive, alpha, and transmission inputs. Baked
textures are content-addressed under the material repository and reused by
every later mesh that references the same material.

The PBR path covers all material templates currently present in Ghostline's
equipment catalog: multilayered, metal base (including glitter), mesh decal
(including emissive and parallax), one- and two-sided glass, parallax screen,
signage, and hologram. Unsupported or malformed records fail explicitly
instead of silently producing an untextured material.

For catalog-scale work, index the archives once and export every requested
mesh appearance from a manifest:

```json
{
  "jobs": [
    {
      "mesh": "base\\characters\\garment\\player_equipment\\feet\\item.mesh",
      "appearance": "black_red",
      "output": "C:\\catalog\\item-black-red.glb"
    }
  ]
}
```

Omit `appearance` to export a Blender material sidecar containing every mesh
appearance. This is useful for world-sector projects where the same mesh is
instanced with several appearances. PBR baking still requires one explicit
appearance per job.

```powershell
& $red mesh-export-batch '.\jobs.json' `
  --schema '.\red-schema.json' `
  --archives-root 'H:\Cyberpunk 2077\archive\pc' `
  --material-repo '.\material-repo' `
  --report '.\export-report.json' `
  --pbr --pbr-size 512
```

The batch continues after individual failures and records each outcome in the
report. A non-PBR material-sidecar failure does not discard a successfully
exported GLB: `error` remains `null`, `material_error` contains the warning,
and any stale or partially written `.Material.json` is removed. Archive reads,
mesh decoding, and GLB writes remain fatal in `error`. With `--pbr`, material
export and PBR baking are also fatal because the requested GLB is incomplete.
For example:

```json
{
  "mesh": "base\\worlds\\example.mesh",
  "appearance": null,
  "output": "C:\\catalog\\example.glb",
  "error": null,
  "material_error": "failed to export material sidecar: malformed material data"
}
```

The command exits nonzero only when at least one report row has a fatal
`error`; material warnings are counted separately in the completion summary.
Progress output is bounded for large manifests: it reports the first, last,
and each hundredth completion, plus the first fatal error and first material
warning. The complete per-job diagnostics remain in the report.

Jobs run concurrently through a shared archive index. Use `--threads` to
choose the worker count; zero (the default) uses every available logical CPU.
Shared dependency and PBR-cache writes are locked per resource, so unrelated
work remains parallel while duplicate material references are deduplicated
safely.

An already exported GLB and sidecar can be upgraded independently:

```powershell
& $red pbr-bake '.\item.glb' `
  --sidecar '.\item.Material.json' `
  --appearance 'denim_blue_red' `
  --size 512
```

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

The implementation is validated against:

- 80 authored CR2W resources with byte-identical binary → JSON → binary
  round trips;
- eight typed RedPackage-bearing resources;
- a 301-file archive with byte-identical pack/extract payloads;
- independent extraction and serialization by WolvenKit 8.17.4;
- a base-game `03_night_city.streamingworld` fixture;
- all 186 compressed segments in `basegame_2_mainmenu.archive`, byte-for-byte
  against WolvenKit's native decoder;
- sampled 10,000-segment windows at the start, middle, and late portions of
  `basegame_3_nightcity.archive`;
- clean/native encoder compatibility vectors covering general sparse Huffman,
  compact tANS, multiple LZ distances, scaled offsets, and extended lengths.

Representative warm command-line measurements from the development machine:

| Workflow | ghostline-red | WolvenKit 8.17.4 |
|---|---:|---:|
| Questphase serialize | 89.7 ms | 17.01 s |
| Questphase deserialize | 89.7 ms | 16.92 s |
| Streamingworld serialize | 85.5 ms | 18.69 s |
| Streamingworld deserialize | 81.2 ms | 17.81 s |
| 302-file archive pack | 1.27 s | 10.00 s |
| 302-file archive extract | 0.63 s | 8.07 s |

The current 305-input Ghostline tree (302 packable resources after excluding
temporary/readme files) completed a DLL-free pack in 1.27 s and extract in
0.63 s with zero SHA-256 mismatches. A fresh stock streamingworld scoped
extract took 115 ms; serialize and deserialize took 96 ms and 99 ms, and the
rebuilt CR2W was byte-identical.

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
