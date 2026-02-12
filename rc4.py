from __future__ import annotations

import argparse
import asyncio
from pathlib import Path
from typing import Iterable


class RC4:
    def __init__(self, key: bytes):
        if not key:
            raise ValueError("Key must not be empty")

        self._s = list(range(256))
        self._i = 0
        self._j = 0

        j = 0
        key_len = len(key)
        for i in range(256):
            j = (j + self._s[i] + key[i % key_len]) % 256
            self._s[i], self._s[j] = self._s[j], self._s[i]

    def process(self, data: bytes) -> bytes:
        if not data:
            return b""

        out = bytearray(len(data))
        s = self._s
        i = self._i
        j = self._j
        for idx, byte in enumerate(data):
            i = (i + 1) % 256
            j = (j + s[i]) % 256
            s[i], s[j] = s[j], s[i]
            k = s[(s[i] + s[j]) % 256]
            out[idx] = byte ^ k

        self._i = i
        self._j = j
        return bytes(out)


def _process_file_sync(
    input_path: Path, output_path: Path, key: bytes, chunk_size: int
) -> None:
    cipher = RC4(key)
    with input_path.open("rb") as src, output_path.open("wb") as dst:
        while True:
            chunk = src.read(chunk_size)
            if not chunk:
                break
            dst.write(cipher.process(chunk))


async def encrypt_file(
    input_path: str | Path,
    output_path: str | Path,
    key: bytes,
    chunk_size: int = 64 * 1024,
) -> None:
    await asyncio.to_thread(
        _process_file_sync, Path(input_path), Path(output_path), key, chunk_size
    )


async def decrypt_file(
    input_path: str | Path,
    output_path: str | Path,
    key: bytes,
    chunk_size: int = 64 * 1024,
) -> None:
    await encrypt_file(input_path, output_path, key, chunk_size)


def _parse_args(argv: Iterable[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="RC4 file encrypt/decrypt (async).")
    parser.add_argument("mode", choices=("encrypt", "decrypt"), help="operation")
    parser.add_argument("input", help="input file path")
    parser.add_argument("output", help="output file path")
    key_group = parser.add_mutually_exclusive_group(required=True)
    key_group.add_argument("--key", help="text key (UTF-8)")
    key_group.add_argument(
        "--key-hex",
        help="hex-encoded key, e.g. --key-hex 0123456789abcdef",
    )
    parser.add_argument(
        "--chunk-size",
        type=int,
        default=64 * 1024,
        help="bytes per chunk (default: 65536)",
    )
    return parser.parse_args(argv)


def _key_from_args(args: argparse.Namespace) -> bytes:
    if args.key is not None:
        return args.key.encode("utf-8")
    try:
        return bytes.fromhex(args.key_hex)
    except ValueError as exc:
        raise SystemExit(f"Invalid hex key: {args.key_hex}") from exc


def _run_cli() -> None:
    args = _parse_args()
    key = _key_from_args(args)

    if args.mode == "encrypt":
        coro = encrypt_file(args.input, args.output, key, args.chunk_size)
    else:
        coro = decrypt_file(args.input, args.output, key, args.chunk_size)

    asyncio.run(coro)


if __name__ == "__main__":
    _run_cli()

