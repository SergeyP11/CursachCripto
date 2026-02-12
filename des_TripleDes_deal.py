class CipherMode(str, Enum):
    ECB = "ECB"
    CBC = "CBC"
    PCBC = "PCBC"
    CFB = "CFB"
    OFB = "OFB"
    CTR = "CTR"
    RANDOM_DELTA = "RandomDelta"


class PaddingMode(str, Enum):
    ZEROS = "Zeros"
    ANSI_X923 = "ANSI_X9_23"
    PKCS7 = "PKCS7"
    ISO_10126 = "ISO_10126"


BLOCK_SIZE = 8


def _xor_bytes(a: bytes, b: bytes) -> bytes:
    return bytes(x ^ y for x, y in zip(a, b))



def pad(data: bytes, block_size: int, mode: PaddingMode) -> bytes:
    pad_len = (block_size - (len(data) % block_size)) % block_size
    if pad_len == 0:
        pad_len = block_size

    if mode == PaddingMode.ZEROS:
        return data + b"\x00" * pad_len

    if mode == PaddingMode.ANSI_X923:
        return data + b"\x00" * (pad_len - 1) + bytes([pad_len])

    if mode == PaddingMode.PKCS7:
        return data + bytes([pad_len]) * pad_len

    if mode == PaddingMode.ISO_10126:
        if pad_len == 1:
            return data + bytes([pad_len])
        random_bytes = secrets.token_bytes(pad_len - 1)
        return data + random_bytes + bytes([pad_len])

    raise ValueError(f"Неизвестный режим набивки: {mode}")


def unpad(data: bytes, block_size: int, mode: PaddingMode) -> bytes:
    if not data or len(data) % block_size != 0:
        raise ValueError("Неверная длина данных для удаления набивки")

    if mode == PaddingMode.ZEROS:
        i = len(data)
        while i > 0 and data[i - 1] == 0:
            i -= 1
        return data[:i]

    last = data[-1]
    if last == 0 or last > block_size:
        raise ValueError("Некорректная набивка")

    if mode in (PaddingMode.ANSI_X923, PaddingMode.PKCS7, PaddingMode.ISO_10126):
        pad_len = last
        if pad_len > len(data):
            raise ValueError("Некорректная набивка")
        if mode == PaddingMode.ANSI_X923:
            if any(data[-pad_len:-1]):
                raise ValueError("Некорректная ANSI X9.23 набивка")
        if mode == PaddingMode.PKCS7:
            if data[-pad_len:] != bytes([pad_len]) * pad_len:
                raise ValueError("Некорректная PKCS7 набивка")
        return data[:-pad_len]

    raise ValueError(f"Неизвестный режим набивки: {mode}")


IP = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7,
]

FP = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25,
]

E = [
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1,
]

P = [
    16, 7, 20, 21,
    29, 12, 28, 17,
    1, 15, 23, 26,
    5, 18, 31, 10,
    2, 8, 24, 14,
    32, 27, 3, 9,
    19, 13, 30, 6,
    22, 11, 4, 25,
]

S_BOXES = [
    # S1
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
    ],
    # S2
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
    ],
    # S3
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
    ],
    # S4
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
    ],
    # S5
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
    ],
    # S6
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
    ],
    # S7
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
    ],
    # S8
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
    ],
]

PC1 = [
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4,
]

PC2 = [
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32,
]

SHIFTS = [
    1, 1, 2, 2, 2, 2, 2, 2,
    1, 2, 2, 2, 2, 2, 2, 1,
]


def _permute(block: int, table: Iterable[int], in_bits: int) -> int:
    out = 0
    for pos in table:
        out <<= 1
        out |= (block >> (in_bits - pos)) & 1
    return out


def _left_rotate_28(x: int, n: int) -> int:
    return ((x << n) & 0x0FFFFFFF) | (x >> (28 - n))


def _bytes_to_int(b: bytes) -> int:
    return int.from_bytes(b, "big")


def _int_to_bytes(x: int, length: int) -> bytes:
    return x.to_bytes(length, "big")


class DES:
    block_size = BLOCK_SIZE
    key_size = 8

    def __init__(self, key: bytes):
        if len(key) != self.key_size:
            raise ValueError("Ключ DES должен быть длиной 8 байт")
        self.subkeys = self._generate_subkeys(key)

    @staticmethod
    def _generate_subkeys(key: bytes) -> Tuple[int, ...]:
        key_int = _bytes_to_int(key)
        # PC1: 64 -> 56 бит
        permuted = _permute(key_int, PC1, 64)
        c = (permuted >> 28) & 0x0FFFFFFF
        d = permuted & 0x0FFFFFFF

        subkeys = []
        for shift in SHIFTS:
            c = _left_rotate_28(c, shift)
            d = _left_rotate_28(d, shift)
            cd = (c << 28) | d
            subkey = _permute(cd, PC2, 56)  # 56 -> 48 бит
            subkeys.append(subkey)
        return tuple(subkeys)

    @staticmethod
    def _f(r: int, k: int) -> int:
        e_r = _permute(r, E, 32)
        x = e_r ^ k

        out = 0
        for i in range(8):
            chunk = (x >> (42 - 6 * i)) & 0x3F
            row = ((chunk & 0x20) >> 4) | (chunk & 0x1)
            col = (chunk >> 1) & 0xF
            s_val = S_BOXES[i][row][col]
            out = (out << 4) | s_val

        return _permute(out, P, 32)

    def encrypt_block(self, block: bytes) -> bytes:
        if len(block) != self.block_size:
            raise ValueError("DES блок должен быть длиной 8 байт")

        x = _bytes_to_int(block)
        x = _permute(x, IP, 64)
        l = (x >> 32) & 0xFFFFFFFF
        r = x & 0xFFFFFFFF

        for k in self.subkeys:
            l, r = r, l ^ self._f(r, k)

        preoutput = (r << 32) | l
        y = _permute(preoutput, FP, 64)
        return _int_to_bytes(y, 8)

    def decrypt_block(self, block: bytes) -> bytes:
        if len(block) != self.block_size:
            raise ValueError("DES блок должен быть длиной 8 байт")

        x = _bytes_to_int(block)
        x = _permute(x, IP, 64)
        l = (x >> 32) & 0xFFFFFFFF
        r = x & 0xFFFFFFFF

        for k in reversed(self.subkeys):
            l, r = r, l ^ self._f(r, k)

        preoutput = (r << 32) | l
        y = _permute(preoutput, FP, 64)
        return _int_to_bytes(y, 8)


class TripleDES:

    block_size = BLOCK_SIZE

    def __init__(self, key: bytes):
        if len(key) not in (16, 24):
            raise ValueError("Ключ TripleDES должен быть 16 или 24 байта")
        if len(key) == 16:
            k1, k2 = key[:8], key[8:]
            k3 = k1
        else:
            k1, k2, k3 = key[:8], key[8:16], key[16:]
        self.des1 = DES(k1)
        self.des2 = DES(k2)
        self.des3 = DES(k3)

    def encrypt_block(self, block: bytes) -> bytes:
        b = self.des1.encrypt_block(block)
        b = self.des2.decrypt_block(b)
        b = self.des3.encrypt_block(b)
        return b

    def decrypt_block(self, block: bytes) -> bytes:
        b = self.des3.decrypt_block(block)
        b = self.des2.encrypt_block(b)
        b = self.des1.decrypt_block(b)
        return b


class DEAL:
    block_size = BLOCK_SIZE
    key_size = 32  # 4 * 8 байт

    def __init__(self, key: bytes):
        if len(key) != self.key_size:
            raise ValueError("Ключ DEAL должен быть длиной 32 байта (256 бит)")
        k1 = key[0:8]
        k2 = key[8:16]
        k3 = key[16:24]
        k4 = key[24:32]
        self.d1 = DES(k1)
        self.d2 = DES(k2)
        self.d3 = DES(k3)
        self.d4 = DES(k4)

    def encrypt_block(self, block: bytes) -> bytes:
        b = self.d1.encrypt_block(block)
        b = self.d2.decrypt_block(b)
        b = self.d3.encrypt_block(b)
        b = self.d4.decrypt_block(b)
        return b

    def decrypt_block(self, block: bytes) -> bytes:
        b = self.d4.encrypt_block(block)
        b = self.d3.decrypt_block(b)
        b = self.d2.encrypt_block(b)
        b = self.d1.decrypt_block(b)
        return b



@dataclass
class BlockCipher:
    cipher: object
    block_size: int

    @classmethod
    def from_algorithm(cls, name: str, key: bytes) -> "BlockCipher":
        name_up = name.upper()
        if name_up == "DES":
            c = DES(key)
        elif name_up in ("3DES", "TRIPLEDES", "TRIPLE_DES"):
            c = TripleDES(key)
        elif name_up == "DEAL":
            c = DEAL(key)
        else:
            raise ValueError(f"Неизвестный алгоритм: {name}")
        return cls(cipher=c, block_size=c.block_size)

    def encrypt_block(self, block: bytes) -> bytes:
        return self.cipher.encrypt_block(block)

    def decrypt_block(self, block: bytes) -> bytes:
        return self.cipher.decrypt_block(block)


def _split_blocks(data: bytes, block_size: int) -> Iterable[bytes]:
    for i in range(0, len(data), block_size):
        yield data[i:i + block_size]


def encrypt(
    cipher: BlockCipher,
    data: bytes,
    mode: CipherMode,
    padding_mode: PaddingMode = PaddingMode.PKCS7,
    iv: bytes | None = None,
    nonce: bytes | None = None,
) -> Tuple[bytes, bytes]:

    block_size = cipher.block_size
    data_p = pad(data, block_size, padding_mode)

    if mode == CipherMode.ECB:
        out = b"".join(cipher.encrypt_block(b) for b in _split_blocks(data_p, block_size))
        return out, b""

    if mode in (CipherMode.CBC, CipherMode.PCBC, CipherMode.CFB, CipherMode.OFB, CipherMode.RANDOM_DELTA):
        if iv is None:
            iv = secrets.token_bytes(block_size)
        if len(iv) != block_size:
            raise ValueError("IV имеет неверную длину")

    if mode == CipherMode.CTR:
        if nonce is None:
            nonce = secrets.token_bytes(block_size)
        if len(nonce) != block_size:
            raise ValueError("Nonce имеет неверную длину")

    if mode == CipherMode.CBC:
        prev = iv
        out_blocks = []
        for block in _split_blocks(data_p, block_size):
            x = _xor_bytes(block, prev)
            y = cipher.encrypt_block(x)
            out_blocks.append(y)
            prev = y
        return b"".join(out_blocks), iv

    if mode == CipherMode.PCBC:
        prev_plain = iv
        prev_cipher = iv
        out_blocks = []
        for block in _split_blocks(data_p, block_size):
            x = _xor_bytes(block, _xor_bytes(prev_plain, prev_cipher))
            y = cipher.encrypt_block(x)
            out_blocks.append(y)
            prev_plain = block
            prev_cipher = y
        return b"".join(out_blocks), iv

    if mode == CipherMode.CFB:
        prev = iv
        out_blocks = []
        for block in _split_blocks(data_p, block_size):
            ks = cipher.encrypt_block(prev)
            c_block = _xor_bytes(block, ks)
            out_blocks.append(c_block)
            prev = c_block
        return b"".join(out_blocks), iv

    if mode == CipherMode.OFB:
        prev = iv
        out_blocks = []
        for block in _split_blocks(data_p, block_size):
            prev = cipher.encrypt_block(prev)
            c_block = _xor_bytes(block, prev)
            out_blocks.append(c_block)
        return b"".join(out_blocks), iv

    if mode == CipherMode.CTR:
        counter_int = _bytes_to_int(nonce)
        out_blocks = []
        for block in _split_blocks(data_p, block_size):
            ctr_block = _int_to_bytes(counter_int, block_size)
            ks = cipher.encrypt_block(ctr_block)
            c_block = _xor_bytes(block, ks)
            out_blocks.append(c_block)
            counter_int = (counter_int + 1) & ((1 << (block_size * 8)) - 1)
        return b"".join(out_blocks), nonce

    if mode == CipherMode.RANDOM_DELTA:

        prev = iv
        out_blocks = []
        for index, block in enumerate(_split_blocks(data_p, block_size)):
            idx_bytes = struct.pack(">Q", index)
            delta_in = _xor_bytes(iv, idx_bytes[:block_size])
            delta = cipher.encrypt_block(delta_in)
            x = _xor_bytes(block, delta)
            x = _xor_bytes(x, prev)
            y = cipher.encrypt_block(x)
            out_blocks.append(y)
            prev = y
        return b"".join(out_blocks), iv

    raise ValueError(f"Неизвестный режим: {mode}")


def decrypt(
    cipher: BlockCipher,
    data: bytes,
    mode: CipherMode,
    padding_mode: PaddingMode = PaddingMode.PKCS7,
    iv: bytes | None = None,
    nonce: bytes | None = None,
) -> bytes:
    block_size = cipher.block_size

    if len(data) % block_size != 0:
        raise ValueError("Длина шифртекста должна быть кратна размеру блока")

    if mode == CipherMode.ECB:
        plain_p = b"".join(cipher.decrypt_block(b) for b in _split_blocks(data, block_size))
        return unpad(plain_p, block_size, padding_mode)

    if mode in (CipherMode.CBC, CipherMode.PCBC, CipherMode.CFB, CipherMode.OFB, CipherMode.RANDOM_DELTA):
        if iv is None or len(iv) != block_size:
            raise ValueError("IV обязателен и должен быть длиной block_size")

    if mode == CipherMode.CTR:
        if nonce is None or len(nonce) != block_size:
            raise ValueError("Nonce обязателен и должен быть длиной block_size")

    if mode == CipherMode.CBC:
        prev = iv
        out_blocks = []
        for block in _split_blocks(data, block_size):
            x = cipher.decrypt_block(block)
            p_block = _xor_bytes(x, prev)
            out_blocks.append(p_block)
            prev = block
        plain_p = b"".join(out_blocks)
        return unpad(plain_p, block_size, padding_mode)

    if mode == CipherMode.PCBC:
        prev_plain = iv
        prev_cipher = iv
        out_blocks = []
        for block in _split_blocks(data, block_size):
            x = cipher.decrypt_block(block)
            p_block = _xor_bytes(x, _xor_bytes(prev_plain, prev_cipher))
            out_blocks.append(p_block)
            prev_plain = p_block
            prev_cipher = block
        plain_p = b"".join(out_blocks)
        return unpad(plain_p, block_size, padding_mode)

    if mode == CipherMode.CFB:
        prev = iv
        out_blocks = []
        for block in _split_blocks(data, block_size):
            ks = cipher.encrypt_block(prev)
            p_block = _xor_bytes(block, ks)
            out_blocks.append(p_block)
            prev = block
        plain_p = b"".join(out_blocks)
        return unpad(plain_p, block_size, padding_mode)

    if mode == CipherMode.OFB:
        prev = iv
        out_blocks = []
        for block in _split_blocks(data, block_size):
            prev = cipher.encrypt_block(prev)
            p_block = _xor_bytes(block, prev)
            out_blocks.append(p_block)
        plain_p = b"".join(out_blocks)
        return unpad(plain_p, block_size, padding_mode)

    if mode == CipherMode.CTR:
        counter_int = _bytes_to_int(nonce)
        out_blocks = []
        for block in _split_blocks(data, block_size):
            ctr_block = _int_to_bytes(counter_int, block_size)
            ks = cipher.encrypt_block(ctr_block)
            p_block = _xor_bytes(block, ks)
            out_blocks.append(p_block)
            counter_int = (counter_int + 1) & ((1 << (block_size * 8)) - 1)
        plain_p = b"".join(out_blocks)
        return unpad(plain_p, block_size, padding_mode)

    if mode == CipherMode.RANDOM_DELTA:
        prev = iv
        out_blocks = []
        for index, block in enumerate(_split_blocks(data, block_size)):
            x = cipher.decrypt_block(block)
            idx_bytes = struct.pack(">Q", index)
            delta_in = _xor_bytes(iv, idx_bytes[:block_size])
            delta = cipher.encrypt_block(delta_in)
            p_block = _xor_bytes(_xor_bytes(x, prev), delta)
            out_blocks.append(p_block)
            prev = block
        plain_p = b"".join(out_blocks)
        return unpad(plain_p, block_size, padding_mode)

    raise ValueError(f"Неизвестный режим: {mode}")


_DEFAULT_EXECUTOR = ThreadPoolExecutor(max_workers=os.cpu_count() or 4)


def _encrypt_file_sync(
    cipher: BlockCipher,
    in_path: str,
    out_path: str,
    mode: CipherMode,
    padding_mode: PaddingMode,
    iv_or_nonce: bytes | None,
    use_nonce: bool,
) -> bytes:
    with open(in_path, "rb") as f:
        data = f.read()

    if use_nonce:
        ciphertext, value = encrypt(
            cipher,
            data,
            mode,
            padding_mode=padding_mode,
            nonce=iv_or_nonce,
        )
    else:
        ciphertext, value = encrypt(
            cipher,
            data,
            mode,
            padding_mode=padding_mode,
            iv=iv_or_nonce,
        )

    with open(out_path, "wb") as f:
        f.write(ciphertext)

    return value


def _decrypt_file_sync(
    cipher: BlockCipher,
    in_path: str,
    out_path: str,
    mode: CipherMode,
    padding_mode: PaddingMode,
    iv_or_nonce: bytes,
    use_nonce: bool,
) -> None:
    with open(in_path, "rb") as f:
        data = f.read()

    if use_nonce:
        plaintext = decrypt(
            cipher,
            data,
            mode,
            padding_mode=padding_mode,
            nonce=iv_or_nonce,
        )
    else:
        plaintext = decrypt(
            cipher,
            data,
            mode,
            padding_mode=padding_mode,
            iv=iv_or_nonce,
        )

    with open(out_path, "wb") as f:
        f.write(plaintext)


async def encrypt_file_async(
    algorithm: str,
    key: bytes,
    in_path: str,
    out_path: str,
    mode: CipherMode = CipherMode.CBC,
    padding_mode: PaddingMode = PaddingMode.PKCS7,
    iv_or_nonce: bytes | None = None,
    executor: ThreadPoolExecutor | None = None,
) -> bytes:
    cipher = BlockCipher.from_algorithm(algorithm, key)
    use_nonce = mode == CipherMode.CTR
    loop = asyncio.get_running_loop()
    if executor is None:
        executor = _DEFAULT_EXECUTOR

    value = await loop.run_in_executor(
        executor,
        _encrypt_file_sync,
        cipher,
        in_path,
        out_path,
        mode,
        padding_mode,
        iv_or_nonce,
        use_nonce,
    )
    return value


async def decrypt_file_async(
    algorithm: str,
    key: bytes,
    in_path: str,
    out_path: str,
    mode: CipherMode = CipherMode.CBC,
    padding_mode: PaddingMode = PaddingMode.PKCS7,
    iv_or_nonce: bytes | None = None,
    executor: ThreadPoolExecutor | None = None,
) -> None:
    if iv_or_nonce is None:
        raise ValueError("iv_or_nonce обязателен для расшифрования файла")

    cipher = BlockCipher.from_algorithm(algorithm, key)
    use_nonce = mode == CipherMode.CTR
    loop = asyncio.get_running_loop()
    if executor is None:
        executor = _DEFAULT_EXECUTOR

    await loop.run_in_executor(
        executor,
        _decrypt_file_sync,
        cipher,
        in_path,
        out_path,
        mode,
        padding_mode,
        iv_or_nonce,
        use_nonce,
    )


__all__ = [
    "DES",
    "TripleDES",
    "DEAL",
    "BlockCipher",
    "CipherMode",
    "PaddingMode",
    "encrypt",
    "decrypt",
    "encrypt_file_async",
    "decrypt_file_async",
]


