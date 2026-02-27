import asyncio
import concurrent.futures
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Iterable, Tuple


BLOCK_SIZE = 16 


IRREDUCIBLE_POLYNOMIALS_GF2_32: dict[str, int] = {
    "x32_x7_x6_x2_x1": 0x1000000C7,   
    "x32_x7_x6_x2_x0": 0x1000000C5,   
    "x32_x8_x5_x3_x0": 0x100000129,   
    "x32_x6_x4_x2_x0": 0x100000055,  
    "x32_x5_x3_x1_x0": 0x10000002B,   
}


def gf2_32_mult(a: int, b: int, irreducible_poly: int) -> int:
    assert irreducible_poly >= (1 << 32) and bin(irreducible_poly).count("1") >= 2
    p = irreducible_poly & ((1 << 33) - 1)
    result = 0
    a = a & 0xFFFFFFFF
    b = b & 0xFFFFFFFF
    for i in range(32):
        if (b >> i) & 1:
            result ^= a << i
    while result > 0xFFFFFFFF:
        top = result.bit_length() - 1
        result ^= p << (top - 32)
    return result & 0xFFFFFFFF



def _rotl32(x: int, n: int) -> int:
    x = x & 0xFFFFFFFF
    n = n & 31
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def _rotr32(x: int, n: int) -> int:
    x = x & 0xFFFFFFFF
    n = n & 31
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF


def _gen_mask(w: int) -> int:
    w = w & 0xFFFFFFFF
    m = (~w ^ (w << 1)) & (~w ^ (w >> 1)) & 0x7FFFFFFE
    m &= (m >> 1) & (m >> 2) & (m >> 4)
    m = (m | (m << 1) | (m << 2) | (m << 4)) & 0xFFFFFFFF
    return m & 0x7FFFFFFC


_MARS_SBOX_HEX = (
    "09d0c479 28c8ffe0 84aa6c39 9dad7287 7dff9be3 d4268361 c96da1d4 7974cc93 "
    "85d0582e 2a4b5705 1ca16a62 c3bd279d 0f1f25e5 5160372f c695c1fb 4d7ff1e4 "
    "ae5f6bf4 0d72ee46 ff23de8a b1cf8e83 f14902e2 3e981e42 8bf53eb6 7f4bf8ac "
    "83631f83 25970205 76afe784 3a7931d4 4f846450 5c64c3f6 210a5f18 c6986a26 "
    "28f4e826 3a60a81c d340a664 7ea820c4 526687c5 7eddd12b 32a11d1d 9c9ef086 "
    "80f6e831 ab6f04ad 56fb9b53 8b2e095c b68556ae d2250b0d 294a7721 e21fb253 "
    "ae136749 e82aae86 93365104 99404a66 78a784dc b69ba84b 04046793 23db5c1e "
    "46cae1d6 2fe28134 5a223942 1863cd5b c190c6e3 07dfb846 6eb88816 2d0dcc4a "
    "a4ccae59 3798670d cbfa9493 4f481d45 eafc8ca8 db1129d6 b0449e20 0f5407fb "
    "6167d9a8 d1f45763 4daa96c3 3bec5958 ababa014 b6ccd201 38d6279f 02682215 "
    "8f376cd5 092c237e bfc56593 32889d2c 854b3e95 05bb9b43 7dcd5dcd a02e926c "
    "fae527e5 36a1c330 3412e1ae f257f462 3c4f1d71 30a2e809 68e5f551 9c61ba44 "
    "5ded0ab8 75ce09c8 9654f93e 698c0cca 243cb3e4 2b062b97 0f3b8d9e 00e050df "
    "fc5d6166 e35f9288 c079550d 0591aee8 8e531e74 75fe3578 2f6d829a f60b21ae "
    "95e8eb8d 6699486b 901d7d9b fd6d6e31 1090acef e0670dd8 dab2e692 cd6d4365 "
    "e5393514 3af345f0 6241fc4d 460da3a3 7bcf3729 8bf1d1e0 14aac070 1587ed55 "
    "3afd7d3e d2f29e01 29a9d1f6 efb10c53 cf3b870f b414935c 664465ed 024acac7 "
    "59a744c1 1d2936a7 dc580aa6 cf574ca8 040a7a10 6cd81807 8a98be4c accea063 "
    "c33e92b5 d1e0e03d b322517e 2092bd13 386b2c4a 52e8dd58 58656dfb 50820371 "
    "41811896 e337ef7e d39fb119 c97f0df6 68fea01b a150a6e5 55258962 eb6ff41b "
    "d7c9cd7a a619cd9e bcf09576 2672c073 f003fb3c 4ab7a50b 1484126a 487ba9b1 "
    "a64fc9c6 f6957d49 38b06a75 dd805fcd 63d094cf f51c999e 1aa4d343 b8495294 "
    "ce9f8e99 bffcd770 c7c275cc 378453a7 7b21be33 397f41bd 4e94d131 92cc1f98 "
    "5915ea51 99f861b7 c9980a88 1d74fd5f b0a495f8 614deed0 b5778eea 5941792d "
    "fa90c1f8 33f824b4 c4965372 3ff6d550 4ca5fec0 8630e964 5b3fbbd6 7da26a48 "
    "b203231a 04297514 2d639306 2eb13149 16a45272 532459a0 8e5f4872 f966c7d9 "
    "07128dc0 0d44db62 afc8d52d 06316131 d838e7ce 1bc41d00 3a2e8c0f ea83837e "
    "b984737d 13ba4891 c4f8b949 a6d6acb3 a215cdce 8359838b 6bd1aa31 f579dd52 "
    "21b93f93 f5176781 187dfdde e94aeb76 2b38fd54 431de1da ab394825 9ad3048f "
    "dfea32aa 659473e3 623f7863 f3346c59 ab3ab685 3346a90b 6b56443e c6de01f8 "
    "8d421fc0 9b0ed10c 88f1a1e9 54c1f029 7dead57b 8d7ba426 4cf5178a 551a7cca "
    "1a9a5f08 fcd651b9 25605182 e11fc6c3 b6fd9676 337b3027 b7c8eb14 9e5fd030 "
    "6b57e354 ad913cf7 7e16688d 58872a69 2c2fc7df e389ccc6 30738df1 0824a734 "
    "e1797a8b a4a8d57b 5b5d193b c8a8309b 73f9a978 73398d32 0f59573e e9df2b03 "
    "e8a5b6c8 848d0704 98df93c2 720a1dc3 684f259a 943ba848 a6370152 863b5ea3 "
    "d17b978b 6d9b58ef 0a700dd4 a73d36bf 8e6a0829 8695bc14 e35b3447 933ac568 "
    "8894b022 2f511c27 ddfbcc3c 006662b6 117c83fe 4e12b414 c2bca766 3a2fec10 "
    "f4562420 55792e2a 46f5d857 ceda25ce c3601d3b 6c00ab46 efac9c28 b3c35047 "
    "611dfee3 257c3207 fdd58482 3b14d84f 23becb64 a075f3a3 088f8ead 07adf158 "
    "7796943c facabf3d c09730cd f7679969 da44e9ed 2c854c12 35935fa3 2f057d9f "
    "690624f8 1cb0bafd 7b0dbdc6 810f23bb fa929a1a 6d969a17 6742979b 74ac7d05 "
    "010e65c4 86a3d963 f907b5a0 d0042bd3 158d7d03 287a8255 bba8366f 096edc33 "
    "21916a7b 77b56b86 951622f9 a6c5e650 8cea17d1 cd8c62bc a3d63433 358a68fd "
    "0f9b9d3c d6aa295b fe33384a c000738e cd67eb2f e2eb6dc2 97338b02 06c9f246 "
    "419cf1ad 2b83c045 3723f18a cb5b3089 160bead7 5d494656 35f8a74b 1e4e6c9e "
    "000399bd 67466880 b4174831 acf423b2 ca815ab3 5a6395e7 302a67c5 8bdb446b "
    "108f8fa4 10223eda 92b8b48b 7f38d0ee ab2701d4 0262d415 af224a30 b3d88aba "
    "f8b2c3af daf7ef70 cc97d3b7 e9614b6c 2baebff4 70f687cf 386c9156 ce092ee5 "
    "01e87da6 6ce91e6a bb7bcc84 c7922c20 9d3b71fd 060e41c6 d7590f15 4e03bb47 "
    "183c198e 63eeb240 2ddbf49a 6d5cba54 923750af f9e14236 7838162b 59726c72 "
    "81b66760 bb2926c1 48a0ce0d a6c0496d ad43507b 718d496a 9df057af 44b1bde6 "
    "054356dc de7ced35 d51a138b 62088cc9 35830311 c96efca2 686f86ec 8e77cb68 "
    "63e1d6b8 c80f9778 79c491fd 1b4c67f2 72698d7d 5e368c31 f7d95e2e a1d3493f "
    "dcd9433e 896f1552 4bc4ca7a a6d1baf4 a5a96dcc 0bef8b46 a169fda7 74df40b7 "
    "4e208804 9a756607 038e87c8 20211e44 8b7ad4bf c6403f35 1848e36d 80bdb038 "
    "1e62891c 643d2107 bf04d6f8 21092c8c f644f389 0778404e 7b78adb8 a2c52d53 "
    "42157abe a2253e2e 7bf3f4ae 80f594f9 953194e7 77eb92ed b3816930 da8d9336 "
    "bf447469 f26d9483 ee6faed5 71371235 de425f73 b4e59f43 7dbe2d4e 2d37b185 "
    "49dc9a63 98c39d98 1301c9a2 389b1bbf 0c18588d a421c1ba 7aa3865c 71e08558 "
    "3c5cfcaa 7d239ca4 0297d9dd d7dc2830 4b37802b 7428ab54 aeee0347 4b3fbb85 "
    "692f2f08 134e578e 36d9e0bf ae8b5fcf edb93ecf 2b27248e 170eb1ef 7dc57fd6 "
    "1e760f16 b1136601 864e1b9b d7ea7319 3ab871bd cfa4d76f e31bd782 0dbeb469 "
    "abb96061 5370f85d ffb07e37 da30d0fb ebc977b6 0b98b40f 3a4d0fe6 df4fc26b "
    "159cf22a c298d6e2 2b78ef6a 61a94ac0 ab561187 14eea0f0 df0d4164 19af70ee "
)
MARS_SBOX: tuple[int, ...] = tuple(int(x, 16) for x in _MARS_SBOX_HEX.split())


def _mars_key_schedule(key: bytes, _irreducible_poly: int = 0) -> list[int]:
   
    if len(key) < 16:
        key = (key * ((16 // len(key)) + 1))[:16]
    key = key[: (len(key) // 4) * 4]
    n = max(4, len(key) // 4)
    T = [int.from_bytes(key[i : i + 4], "little") for i in range(0, len(key), 4)]
    T = (T + [0] * 15)[:15]
    T[n] = n
    for i in range(n + 1, 15):
        T[i] = 0
    K: list[int] = [0] * 40
    for j in range(4):
        for i in range(15):
            T[i] = (T[i] ^ _rotl32((T[(i + 8) % 15] ^ T[(i + 13) % 15]) & 0xFFFFFFFF, 3) ^ (4 * i + j)) & 0xFFFFFFFF
        for _ in range(4):
            for i in range(15):
                T[i] = _rotl32((T[i] + MARS_SBOX[T[(i + 14) % 15] & 511]) & 0xFFFFFFFF, 9) & 0xFFFFFFFF
        for i in range(10):
            K[10 * j + i] = T[(4 * i) % 15] & 0xFFFFFFFF
    for i in range(5, 37, 2):
        w = (K[i] | 3) & 0xFFFFFFFF
        m = _gen_mask(w)
        if m:
            K[i] = (w ^ (_rotl32(MARS_SBOX[265 + (K[i] & 3)], K[i - 1] & 31) & m)) & 0xFFFFFFFF
    return K


def _mars_encrypt_block(block: bytes, k: list[int]) -> bytes:
    a = int.from_bytes(block[0:4], "little") + k[0]
    b = int.from_bytes(block[4:8], "little") + k[1]
    c = int.from_bytes(block[8:12], "little") + k[2]
    d = int.from_bytes(block[12:16], "little") + k[3]
    a, b, c, d = a & 0xFFFFFFFF, b & 0xFFFFFFFF, c & 0xFFFFFFFF, d & 0xFFFFFFFF
    for i in range(8):
        b = (b ^ MARS_SBOX[a & 0xFF]) & 0xFFFFFFFF
        b = (b + MARS_SBOX[256 + ((a >> 8) & 0xFF)]) & 0xFFFFFFFF
        c = (c + MARS_SBOX[(a >> 16) & 0xFF]) & 0xFFFFFFFF
        a = _rotr32(a, 24)
        d = (d ^ MARS_SBOX[256 + (a & 0xFF)]) & 0xFFFFFFFF
        if i % 4 == 0:
            a = (a + d) & 0xFFFFFFFF
        elif i % 4 == 1:
            a = (a + b) & 0xFFFFFFFF
        a, b, c, d = b, c, d, a
    for i in range(16):
        t = _rotl32(a, 13)
        r = _rotl32((t * k[2 * i + 5]) & 0xFFFFFFFF, 10)
        m = (a + k[2 * i + 4]) & 0xFFFFFFFF
        r5 = _rotr32(r, 5)
        amt = r5 & 0x1F
        l = _rotl32((MARS_SBOX[m & 511] ^ r5 ^ r) & 0xFFFFFFFF, amt)
        c = (c + _rotl32(m, amt)) & 0xFFFFFFFF
        if i < 8:
            b = (b + l) & 0xFFFFFFFF
            d = (d ^ r) & 0xFFFFFFFF
        else:
            d = (d + l) & 0xFFFFFFFF
            b = (b ^ r) & 0xFFFFFFFF
        a, b, c, d = b, c, d, t
    for i in range(8):
        if i % 4 == 2:
            a = (a - d) & 0xFFFFFFFF
        elif i % 4 == 3:
            a = (a - b) & 0xFFFFFFFF
        b = (b ^ MARS_SBOX[256 + (a & 0xFF)]) & 0xFFFFFFFF
        c = (c - MARS_SBOX[(a >> 24) & 0xFF]) & 0xFFFFFFFF
        t = _rotl32(a, 24)
        d = (d - MARS_SBOX[256 + ((a >> 16) & 0xFF)]) & 0xFFFFFFFF
        d = (d ^ MARS_SBOX[t & 0xFF]) & 0xFFFFFFFF
        a, b, c, d = b, c, d, t
    a = (a - k[36]) & 0xFFFFFFFF
    b = (b - k[37]) & 0xFFFFFFFF
    c = (c - k[38]) & 0xFFFFFFFF
    d = (d - k[39]) & 0xFFFFFFFF
    return (
        a.to_bytes(4, "little") + b.to_bytes(4, "little") + c.to_bytes(4, "little") + d.to_bytes(4, "little")
    )


def _mars_decrypt_block(block: bytes, k: list[int]) -> bytes:
    d = int.from_bytes(block[0:4], "little") + k[36]
    c = int.from_bytes(block[4:8], "little") + k[37]
    b = int.from_bytes(block[8:12], "little") + k[38]
    a = int.from_bytes(block[12:16], "little") + k[39]
    d, c, b, a = d & 0xFFFFFFFF, c & 0xFFFFFFFF, b & 0xFFFFFFFF, a & 0xFFFFFFFF
    for i in range(8):
        b = (b ^ MARS_SBOX[a & 0xFF]) & 0xFFFFFFFF
        b = (b + MARS_SBOX[256 + ((a >> 8) & 0xFF)]) & 0xFFFFFFFF
        c = (c + MARS_SBOX[(a >> 16) & 0xFF]) & 0xFFFFFFFF
        a = _rotr32(a, 24)
        d = (d ^ MARS_SBOX[256 + (a & 0xFF)]) & 0xFFFFFFFF
        if i % 4 == 0:
            a = (a + d) & 0xFFFFFFFF
        elif i % 4 == 1:
            a = (a + b) & 0xFFFFFFFF
        a, b, c, d = b, c, d, a
    for i in range(16):
        t = _rotr32(a, 13)
        r = _rotl32((a * k[35 - 2 * i]) & 0xFFFFFFFF, 10)
        m = (t + k[34 - 2 * i]) & 0xFFFFFFFF
        r5 = _rotr32(r, 5)
        amt = r5 & 0x1F
        l = _rotl32((MARS_SBOX[m & 511] ^ r5 ^ r) & 0xFFFFFFFF, amt)
        c = (c - _rotl32(m, amt)) & 0xFFFFFFFF
        if i < 8:
            b = (b - l) & 0xFFFFFFFF
            d = (d ^ r) & 0xFFFFFFFF
        else:
            d = (d - l) & 0xFFFFFFFF
            b = (b ^ r) & 0xFFFFFFFF
        a, b, c, d = b, c, d, t
    for i in range(8):
        if i % 4 == 2:
            a = (a - d) & 0xFFFFFFFF
        elif i % 4 == 3:
            a = (a - b) & 0xFFFFFFFF
        b = (b ^ MARS_SBOX[256 + (a & 0xFF)]) & 0xFFFFFFFF
        c = (c - MARS_SBOX[(a >> 24) & 0xFF]) & 0xFFFFFFFF
        t = _rotl32(a, 24)
        d = (d - MARS_SBOX[256 + ((a >> 16) & 0xFF)]) & 0xFFFFFFFF
        d = (d ^ MARS_SBOX[t & 0xFF]) & 0xFFFFFFFF
        a, b, c, d = b, c, d, t
    d = (d - k[0]) & 0xFFFFFFFF
    c = (c - k[1]) & 0xFFFFFFFF
    b = (b - k[2]) & 0xFFFFFFFF
    a = (a - k[3]) & 0xFFFFFFFF
    return (
        d.to_bytes(4, "little") + c.to_bytes(4, "little") + b.to_bytes(4, "little") + a.to_bytes(4, "little")
    )


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


USE_FULL_MARS_CORE = True


@dataclass
class MarsCipher:
    key: bytes
    irreducible_poly: int = field(
        default_factory=lambda: IRREDUCIBLE_POLYNOMIALS_GF2_32["x32_x7_x6_x2_x0"],
        repr=False,
    )

    def __post_init__(self) -> None:
        if not self.key:
            raise ValueError("Key must not be empty")
        if not ((1 << 32) <= self.irreducible_poly < (1 << 33)):
            raise ValueError("Irreducible polynomial must have degree 32 (bit 32 set)")
        self._l_key = _mars_key_schedule(self.key, self.irreducible_poly)
        self._block_key = b"".join(
            (self._l_key[i] & 0xFFFFFFFF).to_bytes(4, "big") for i in range(4)
        )

   
    def encrypt_block(self, block: bytes) -> bytes:
        if len(block) != BLOCK_SIZE:
            raise ValueError("Block size must be 16 bytes")
        if USE_FULL_MARS_CORE:
            return _mars_encrypt_block(block, self._l_key)
        return _xor_blocks(block, self._block_key)

    def decrypt_block(self, block: bytes) -> bytes:
        if len(block) != BLOCK_SIZE:
            raise ValueError("Block size must be 16 bytes")
        if USE_FULL_MARS_CORE:
            return _mars_decrypt_block(block, self._l_key)
        return _xor_blocks(block, self._block_key)

    
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
            result.append(delta.to_bytes(BLOCK_SIZE, "big"))  
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
    irreducible_poly: int | None = None,
) -> None:
    loop = asyncio.get_running_loop()
    cipher = MarsCipher(key, irreducible_poly=irreducible_poly or IRREDUCIBLE_POLYNOMIALS_GF2_32["x32_x7_x6_x2_x0"])
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

    parser = argparse.ArgumentParser(description="MARS(упрощённое ядро).")
    parser.add_argument("action", choices=["encrypt", "decrypt"], help="encrypt/decrypt")
    parser.add_argument("mode", choices=[m.value for m in Mode], help="режим шифрования")
    parser.add_argument("src", nargs="+", help="входные файлы")
    parser.add_argument("-o", "--output-dir", required=True, help="директория для выходных файлов")
    parser.add_argument("-k", "--key", required=True, help="ключ (строка, будет интерпретирована как UTF-8)")
    parser.add_argument("-p", "--padding", choices=[p.value for p in Padding], default=Padding.PKCS7.value)
    parser.add_argument("--iv-hex", help="IV в hex (16 байт, только для поточных/цепочечных режимов)")
    parser.add_argument(
        "--poly",
        choices=list(IRREDUCIBLE_POLYNOMIALS_GF2_32),
        default="x32_x7_x6_x2_x0",
        help="неприводимый полином для GF(2^32)",
    )

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
    poly = IRREDUCIBLE_POLYNOMIALS_GF2_32[args.poly]
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
            irreducible_poly=poly,
        )
    )


if __name__ == "__main__":
    main()

