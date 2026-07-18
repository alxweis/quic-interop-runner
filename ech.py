import os
import struct
from pathlib import Path

from Crypto.PublicKey import ECC


ECH_VERSION = 0xFE0D
KEM_X25519_HKDF_SHA256 = 0x0020
KDF_HKDF_SHA256 = 0x0001
AEAD_AES_128_GCM = 0x0001


def generate_ech_material(directory: str) -> None:
    """Generate an RFC 9849 ECHConfigList and matching X25519 key."""

    output_dir = Path(directory)
    output_dir.mkdir(parents=True, exist_ok=True)

    key = ECC.generate(curve="Curve25519")
    private_key = bytes(key.seed)
    public_key = key.public_key().export_key(format="raw")

    config_id = os.urandom(1)[0]
    public_name = b"public.example"

    cipher_suites = struct.pack(
        "!HH",
        KDF_HKDF_SHA256,
        AEAD_AES_128_GCM,
    )

    config_contents = b"".join(
        [
            struct.pack("!B", config_id),
            struct.pack("!H", KEM_X25519_HKDF_SHA256),
            struct.pack("!H", len(public_key)),
            public_key,
            struct.pack("!H", len(cipher_suites)),
            cipher_suites,
            struct.pack("!B", 0),  # maximum_name_length
            struct.pack("!B", len(public_name)),
            public_name,
            struct.pack("!H", 0),  # extensions
        ]
    )

    ech_config = b"".join(
        [
            struct.pack("!H", ECH_VERSION),
            struct.pack("!H", len(config_contents)),
            config_contents,
        ]
    )

    ech_config_list = struct.pack("!H", len(ech_config)) + ech_config

    (output_dir / "ech_config.bin").write_bytes(ech_config)
    (output_dir / "ech_config_list.bin").write_bytes(ech_config_list)
    (output_dir / "ech_private_key.bin").write_bytes(private_key)