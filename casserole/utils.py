from __future__ import annotations


def read_exactly(f, size: int) -> bytes:
    result = b""

    while len(result) < size:
        chunk = f.read(size - len(result))

        if not chunk and len(result) != size:
            raise ValueError(f"Could only read {len(result)} of {size} bytes!")

        result += chunk

    return result


def pretty_bytes(data: bytes) -> str:
    return "<" + " ".join(f"{c:02X}" for c in data) + ">"
