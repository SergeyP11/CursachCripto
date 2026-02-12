import asyncio
import concurrent.futures
from dataclasses import dataclass
from enum import Enum
from pathlib import Path
from typing import Iterable, Tuple


BLOCK_SIZE = 16  # 128 бит


class Mode(str, Enum):
    ECB = "ECB"
    CBC = "CBC"
    PCBC = "PCBC"
    CFB = "CFB"
    OFB = "OFB"
    CTR = "CTR"
    RANDOM_DELTA = "RandomDelta"


class Padding(str, Enum):
    ZEROS = "Zeros"
    ANSI_X923 = "ANSI_X9.23"
    PKCS7 = "PKCS7"
    ISO_10126 = "ISO_10126"


def _xor_blocks(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))


def _chunks(data: bytes, size: int) -> Iterable[bytes]:
    for i in range(0, len(data), size):
        yield data[i : i + size]


def pad(data: bytes, padding: Padding) -> bytes:
    pad_len = (BLOCK_SIZE - (len(data) % BLOCK_SIZE)) % BLOCK_SIZE
    if pad_len == 0 and padding in (Padding.PKCS7, Padding.ANSI_X923, Padding.ISO_10126):
        pad_len = BLOCK_SIZE

    if padding == Padding.ZEROS:
        return data + b"\x00" * pad_len
    if padding == Padding.PKCS7:
        return data + bytes([pad_len]) * pad_len
    if padding == Padding.ANSI_X923:
        return data + b"\x00" * (pad_len - 1) + bytes([pad_len])
    if padding == Padding.ISO_10126:
        import os

        if pad_len <= 1:
            return data + bytes([pad_len])
        random_bytes = os.urandom(pad_len - 1)
        return data + random_bytes + bytes([pad_len])
    raise ValueError("Unknown padding")


def unpad(data: bytes, padding: Padding) -> bytes:
    if padding == Padding.ZEROS:
        return data.rstrip(b"\x00")
    if not data:
        return data
    if padding in (Padding.PKCS7, Padding.ANSI_X923, Padding.ISO_10126):
        pad_len = data[-1]
        if pad_len == 0 or pad_len > BLOCK_SIZE or pad_len > len(data):
            raise ValueError("Invalid padding")
        return data[:-pad_len]
    raise ValueError("Unknown padding")


@dataclass
class MarsCipher:
    key: bytes

    def __post_init__(self) -> None:
        if not self.key:
            raise ValueError("Key must not be empty")
        self._expanded_key = self._expand_key(self.key)

    def _expand_key(self, key: bytes) -> bytes:
        while len(key) < BLOCK_SIZE:
            key += key
        return key[: BLOCK_SIZE]

    def encrypt_block(self, block: bytes) -> bytes:
        if len(block) != BLOCK_SIZE:
            raise ValueError("Block size must be 16 bytes")
        return _xor_blocks(block, self._expanded_key)

    def decrypt_block(self, block: bytes) -> bytes:
        return self.encrypt_block(block)

    def encrypt(self, data: bytes, mode: Mode, iv: bytes | None = None, padding: Padding = Padding.PKCS7) -> bytes:
        if mode in (Mode.CBC, Mode.PCBC, Mode.CFB, Mode.OFB, Mode.CTR, Mode.RANDOM_DELTA) and (iv is None or len(iv) != BLOCK_SIZE):
            raise ValueError("IV must be 16 bytes for this mode")

        if mode in (Mode.ECB, Mode.CBC, Mode.PCBC, Mode.RANDOM_DELTA):
            data = pad(data, padding)

        blocks = list(_chunks(data, BLOCK_SIZE))
        result: list[bytes] = []

        if mode == Mode.ECB:
            for b in blocks:
                result.append(self.encrypt_block(b))

        elif mode == Mode.CBC:
            prev = iv
            for b in blocks:
                x = _xor_blocks(b, prev)
                c = self.encrypt_block(x)
                result.append(c)
                prev = c

        elif mode == Mode.PCBC:
            prev_p = iv
            prev_c = iv
            for b in blocks:
                x = _xor_blocks(_xor_blocks(b, prev_p), prev_c)
                c = self.encrypt_block(x)
                result.append(c)
                prev_p, prev_c = b, c

        elif mode == Mode.CFB:
            prev = iv
            for b in blocks:
                s = self.encrypt_block(prev)
                c = _xor_blocks(b, s[: len(b)])
                result.append(c)
                prev = c

        elif mode == Mode.OFB:
            prev = iv
            for b in blocks:
                prev = self.encrypt_block(prev)
                c = _xor_blocks(b, prev[: len(b)])
                result.append(c)

        elif mode == Mode.CTR:
            counter = int.from_bytes(iv, "big")
            for b in blocks:
                ctr_block = counter.to_bytes(BLOCK_SIZE, "big")
                s = self.encrypt_block(ctr_block)
                c = _xor_blocks(b, s[: len(b)])
                result.append(c)
                counter = (counter + 1) % (1 << (BLOCK_SIZE * 8))

        elif mode == Mode.RANDOM_DELTA:
            import os

            delta = int.from_bytes(os.urandom(BLOCK_SIZE), "big")
            counter = int.from_bytes(iv, "big")
            result.append(delta.to_bytes(BLOCK_SIZE, "big"))  # первый блок – случайное дельта
            for b in blocks:
                ctr_block = counter.to_bytes(BLOCK_SIZE, "big")
                s = self.encrypt_block(ctr_block)
                c = _xor_blocks(b, s[: len(b)])
                result.append(c)
                counter = (counter + delta) % (1 << (BLOCK_SIZE * 8))
        else:
            raise ValueError("Unsupported mode")

        return b"".join(result)

    def decrypt(self, data: bytes, mode: Mode, iv: bytes | None = None, padding: Padding = Padding.PKCS7) -> bytes:
        if mode in (Mode.CBC, Mode.PCBC, Mode.CFB, Mode.OFB, Mode.CTR, Mode.RANDOM_DELTA) and (iv is None or len(iv) != BLOCK_SIZE):
            raise ValueError("IV must be 16 bytes for this mode")

        if mode == Mode.RANDOM_DELTA:
            if len(data) < BLOCK_SIZE:
                raise ValueError("RandomDelta: data too short")
            delta = int.from_bytes(data[:BLOCK_SIZE], "big")
            data_body = data[BLOCK_SIZE:]
        else:
            delta = 0
            data_body = data

        blocks = list(_chunks(data_body, BLOCK_SIZE))
        result: list[bytes] = []

        if mode == Mode.ECB:
            for b in blocks:
                result.append(self.decrypt_block(b))

        elif mode == Mode.CBC:
            prev = iv
            for b in blocks:
                x = self.decrypt_block(b)
                p = _xor_blocks(x, prev)
                result.append(p)
                prev = b

        elif mode == Mode.PCBC:
            prev_p = iv
            prev_c = iv
            for b in blocks:
                x = self.decrypt_block(b)
                p = _xor_blocks(_xor_blocks(x, prev_p), prev_c)
                result.append(p)
                prev_p, prev_c = p, b

        elif mode == Mode.CFB:
            prev = iv
            for b in blocks:
                s = self.encrypt_block(prev)
                p = _xor_blocks(b, s[: len(b)])
                result.append(p)
                prev = b

        elif mode == Mode.OFB:
            prev = iv
            for b in blocks:
                prev = self.encrypt_block(prev)
                p = _xor_blocks(b, prev[: len(b)])
                result.append(p)

        elif mode == Mode.CTR:
            counter = int.from_bytes(iv, "big")
            for b in blocks:
                ctr_block = counter.to_bytes(BLOCK_SIZE, "big")
                s = self.encrypt_block(ctr_block)
                p = _xor_blocks(b, s[: len(b)])
                result.append(p)
                counter = (counter + 1) % (1 << (BLOCK_SIZE * 8))

        elif mode == Mode.RANDOM_DELTA:
            counter = int.from_bytes(iv, "big")
            for b in blocks:
                ctr_block = counter.to_bytes(BLOCK_SIZE, "big")
                s = self.encrypt_block(ctr_block)
                p = _xor_blocks(b, s[: len(b)])
                result.append(p)
                counter = (counter + delta) % (1 << (BLOCK_SIZE * 8))
        else:
            raise ValueError("Unsupported mode")

        plaintext = b"".join(result)
        if mode in (Mode.ECB, Mode.CBC, Mode.PCBC, Mode.RANDOM_DELTA):
            plaintext = unpad(plaintext, padding)
        return plaintext


def _process_file_sync(
    cipher: MarsCipher,
    src: Path,
    dst: Path,
    encrypt_flag: bool,
    mode: Mode,
    iv: bytes | None,
    padding: Padding,
) -> None:
    data = src.read_bytes()
    if encrypt_flag:
        result = cipher.encrypt(data, mode=mode, iv=iv, padding=padding)
    else:
        result = cipher.decrypt(data, mode=mode, iv=iv, padding=padding)
    dst.write_bytes(result)


async def process_files(
    key: bytes,
    files: Iterable[Tuple[Path, Path, bool]],
    mode: Mode,
    iv: bytes | None,
    padding: Padding,
    max_workers: int | None = None,
) -> None:
    loop = asyncio.get_running_loop()
    cipher = MarsCipher(key)
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        tasks = [
            loop.run_in_executor(
                pool,
                _process_file_sync,
                cipher,
                src,
                dst,
                encrypt_flag,
                mode,
                iv,
                padding,
            )
            for src, dst, encrypt_flag in files
        ]
        await asyncio.gather(*tasks)


def main() -> None:
    import argparse
    import os

    parser = argparse.ArgumentParser(description="MARS cipher demo (упрощённое ядро).")
    parser.add_argument("action", choices=["encrypt", "decrypt"], help="encrypt/decrypt")
    parser.add_argument("mode", choices=[m.value for m in Mode], help="режим шифрования")
    parser.add_argument("src", nargs="+", help="входные файлы")
    parser.add_argument("-o", "--output-dir", required=True, help="директория для выходных файлов")
    parser.add_argument("-k", "--key", required=True, help="ключ (строка, будет интерпретирована как UTF-8)")
    parser.add_argument("-p", "--padding", choices=[p.value for p in Padding], default=Padding.PKCS7.value)
    parser.add_argument("--iv-hex", help="IV в hex (16 байт, только для поточных/цепочечных режимов)")

    args = parser.parse_args()

    mode = Mode(args.mode)
    padding = Padding(args.padding)

    iv: bytes | None = None
    if mode in (Mode.CBC, Mode.PCBC, Mode.CFB, Mode.OFB, Mode.CTR, Mode.RANDOM_DELTA):
        if not args.iv_hex:
            raise SystemExit("Для выбранного режима необходимо указать --iv-hex (32 hex-символа)")
        iv = bytes.fromhex(args.iv_hex)
        if len(iv) != BLOCK_SIZE:
            raise SystemExit("IV должен быть 16 байт (32 hex-символа)")

    key_bytes = args.key.encode("utf-8")
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    file_pairs: list[Tuple[Path, Path, bool]] = []
    for src_str in args.src:
        src = Path(src_str)
        if not src.is_file():
            raise SystemExit(f"Файл не найден: {src}")
        suffix = ".enc" if args.action == "encrypt" else ".dec"
        dst = output_dir / (src.name + suffix)
        file_pairs.append((src, dst, args.action == "encrypt"))

    asyncio.run(
        process_files(
            key=key_bytes,
            files=file_pairs,
            mode=mode,
            iv=iv,
            padding=padding,
            max_workers=min(4, os.cpu_count() or 1),
        )
    )


if __name__ == "__main__":
    main()

