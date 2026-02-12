from __future__ import annotations
import hashlib
import secrets
from dataclasses import dataclass


@dataclass
class Params:
    p: int
    g: int


@dataclass
class KeyPair:
    private_key: int
    public_key: int


def get_group14_2048() -> Params:
    p_hex = """
        FFFFFFFF FFFFFFFF C90FDAA2 2168C234 C4C6628B 80DC1CD1
        29024E08 8A67CC74 020BBEA6 3B139B22 514A0879 8E3404DD
        EF9519B3 CD3A431B 302B0A6D F25F1437 4FE1356D 6D51C245
        E485B576 625E7EC6 F44C42E9 A637ED6B 0BFF5CB6 F406B7ED
        EE386BFB 5A899FA5 AE9F2411 7C4B1FE6 49286651 ECE45B3D
        C2007CB8 A163BF05 98DA4836 1C55D39A 69163FA8 FD24CF5F
        83655D23 DCA3AD96 1C62F356 208552BB 9ED52907 7096966D
        670C354E 4ABC9804 F1746C08 CA18217C 32905E46 2E36CE3B
        E39E772C 180E8603 9B2783A2 EC07A28F B5C55DF0 6F4C52C9
        DE2BCBF6 95581718 3995497C EA956AE5 15D22618 98FA0510
        15728E5A 8AACAA68 FFFFFFFF FFFFFFFF
    """.strip().replace(" ", "").replace("\n", "")
    p = int(p_hex, 16)
    g = 2
    return Params(p=p, g=g)


def generate_key_pair(params: Params, private_bits: int = 256) -> KeyPair:
    priv = secrets.randbits(private_bits)
    priv |= 1 << (private_bits - 1)
    pub = pow(params.g, priv, params.p)
    return KeyPair(private_key=priv, public_key=pub)


def compute_shared_secret(params: Params, my_private: int, other_public: int) -> int:
    return pow(other_public, my_private, params.p)


def derive_key_sha256(shared_secret: int) -> bytes:
    secret_bytes = shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, "big")
    return hashlib.sha256(secret_bytes).digest()


def hex_prefix(data: bytes, n: int = 16) -> str:
    return "".join(f"{b:02x}" for b in data[:n])


def xor_encrypt(key: bytes, plaintext: bytes) -> bytes:
    return bytes(b ^ key[i % len(key)] for i, b in enumerate(plaintext))


def demo() -> None:
    params = get_group14_2048()
    print(f"Using group p (bits) = {params.p.bit_length()}, g = {params.g}")

    alice_keys = generate_key_pair(params)
    bob_keys = generate_key_pair(params)

    print(f"Alice public: {alice_keys.public_key}")
    print(f"Bob   public: {bob_keys.public_key}")

    alice_shared = compute_shared_secret(params, alice_keys.private_key, bob_keys.public_key)
    bob_shared = compute_shared_secret(params, bob_keys.private_key, alice_keys.public_key)

    assert alice_shared == bob_shared, "Shared secrets must match"

    sym_key = derive_key_sha256(alice_shared)
    print(f"Symmetric key (SHA-256, first bytes): {hex_prefix(sym_key, 16)}...")

    message = b"Diffie-Hellman"
    ciphertext = xor_encrypt(sym_key, message)
    recovered = xor_encrypt(sym_key, ciphertext)

    print(f"Plaintext:  {message}")
    print(f"Ciphertext (hex): {ciphertext.hex()}")
    print(f"Recovered:  {recovered}")
    print("Success!" if recovered == message else "Decryption failed")


if __name__ == "__main__":
    demo()


