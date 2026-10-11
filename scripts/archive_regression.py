"""Unpack historical archives with WolvenKit and verify native repacks independently.

Each case also gets a WolvenKit repack of the same extracted inputs. Archive
sizes are reported, while path/hash identity, segment layout, and extracted
payload SHA-256 values are the compatibility checks. Output must be fresh.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
import sys


def run(command: list[str], log: Path) -> str:
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    log.write_bytes(result.stdout)
    text = result.stdout.decode("utf-8", errors="replace")
    # Some WolvenKit exceptions return exit status zero: inspect output too.
    if result.returncode or "exception" in text.lower():
        raise RuntimeError(f"command failed; see {log}")
    return text


def tree(root: Path) -> dict[str, str]:
    return {
        str(path.relative_to(root)).replace("\\", "/").lower():
            hashlib.sha256(path.read_bytes()).hexdigest()
        for path in root.rglob("*") if path.is_file()
    }


def index(red: str, archive: Path, log: Path) -> dict:
    return json.loads(run([red, "archive-list", str(archive), "--json"], log))


def layout(document: dict) -> dict:
    # Physical offsets, compressed sizes, timestamps and SHA1 conventions can
    # differ between encoders. Logical segment layout must remain identical.
    segments = document["segments"]
    return {
        entry["name_hash"]: {
            "inline_buffers": entry["inline_buffer_segments"],
            "segment_sizes": [segment["size"] for segment in
                segments[entry["segments_start"]:entry["segments_end"]]],
        }
        for entry in document["entries"]
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("archives", nargs="+", type=Path)
    parser.add_argument("--wolvenkit", required=True, type=Path)
    parser.add_argument("--red", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    args.output.mkdir(parents=True, exist_ok=False)
    red, wkit = str(args.red.resolve()), str(args.wolvenkit.resolve())
    report = {"cases": [], "runtime_tested": False}
    for number, archive in enumerate(args.archives):
        case = args.output / f"{number:02d}-{archive.parent.name}"
        case.mkdir()
        result = {"archive": str(archive.resolve()), "passed": False}
        try:
            inputs = case / "input"
            run([wkit, "unbundle", str(archive.resolve()), "-o", str(inputs), "-v", "quiet"],
                case / "original-extract.log")
            original = tree(inputs)
            if not original:
                raise RuntimeError("original archive extracted no files")
            run([red, "pack", str(inputs), "-o", str(case / "native")], case / "native-pack.log")
            run([wkit, "pack", str(inputs), "-o", str(case / "wolvenkit"), "-v", "quiet"],
                case / "wolvenkit-pack.log")
            candidates = {"original": archive.resolve(),
                          "native": case / "native/input.archive",
                          "wolvenkit": case / "wolvenkit/input.archive"}
            layouts = {}
            result["sizes"] = {}
            for name, candidate in candidates.items():
                result["sizes"][name] = candidate.stat().st_size
                document = index(red, candidate, case / f"{name}-index.json")
                layouts[name] = layout(document)
                if name == "original":
                    continue
                extracted = case / f"{name}-extracted"
                run([wkit, "unbundle", str(candidate), "-o", str(extracted), "-v", "quiet"],
                    case / f"{name}-extract.log")
                actual = tree(extracted)
                if actual != original:
                    missing = sorted(original.keys() - actual.keys())
                    extra = sorted(actual.keys() - original.keys())
                    changed = sorted(path for path in original.keys() & actual.keys()
                                     if original[path] != actual[path])
                    raise RuntimeError(f"{name}: missing={missing}, extra={extra}, changed={changed}")
            if not layouts["original"] == layouts["native"] == layouts["wolvenkit"]:
                raise RuntimeError("archive entry hashes or logical segment layouts differ")
            (case / "payload-sha256.json").write_text(json.dumps(original, indent=2) + "\n")
            result.update(passed=True, files=len(original), segments=len(
                index(red, candidates["native"], case / "native-index.json")["segments"]))
        except (RuntimeError, OSError, ValueError) as error:
            result["error"] = str(error)
        report["cases"].append(result)
        (args.output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps(result), flush=True)
    return 0 if all(case["passed"] for case in report["cases"]) else 1


if __name__ == "__main__":
    sys.exit(main())
