# Copy Fail (CVE-2026-31431) - C port

*[English (en)](README.md) ∙ [日本語 (ja)](README.ja.md) ∙ [简体中文 (zh-cn)](README.zh-cn.md)*

Copy Fail Linux 本地提权 (CVE-2026-31431) 的跨平台 C 语言重写版。该漏洞由 Theori / Xint 于 2026 年 4 月 29 日披露。有关完整的漏洞描述、时间线以及 Theori 的发现过程，请参阅 [copy.fail](https://copy.fail/) 上的官方报告。

公开发布的概念验证 (PoC) 是一个 732 字节的 Python 脚本。这个 C 语言移植版证明了相同的漏洞利用可以表示为可移植的 C 代码，并且可以编译到 nolibc 支持的任何架构，而无需在项目自己的源代码中包含特定架构的十六进制 blob 或内联汇编。

此移植版的作者: Tony Gies <tony.gies@crashunited.com>
发现和最初披露: Theori / Xint

## 仓库结构

```
copy-fail-c/
├── exploit.c           释放器 (二进制文件变异变体)
├── exploit-passwd.c    释放器 (/etc/passwd UID 翻转变体)
├── payload.c           被释放的有效载荷主体 (setgid+setuid+execve sh)
├── Makefile            构建编排
├── nolibc/             从 torvalds/linux tools/include/nolibc 引入的代码
└── README.md           本文件
```

运行 `make` 后:

```
├── payload             微小的静态 ELF，作为字节嵌入到释放器中
├── payload.o           通过 `ld -r -b binary` 包装为可重定位 .o 的有效载荷
├── exploit             释放器，二进制文件变异变体
└── exploit-passwd      释放器，/etc/passwd UID 翻转变体
```

`exploit.c` 以只读方式打开目标二进制文件，然后对于嵌入的有效载荷的每个 4 字节窗口，通过 AF_ALG 运行一次伪造的 AEAD 解密。其密文输入是通过 splice() 从目标的页缓存页面提供的。authencesn 模板的原地优化将 splice 的源页面同时视为密文输入和明文目标地址，因此在身份验证验证拒绝该请求时，（注定失败的）解密已经覆盖了页缓存页面。经过 4 * N 次迭代后，目标的缓存映像已被有效载荷逐字节替换。对目标执行 execve() 会加载已变异的页面；磁盘上的 inode 仍然设置了 setuid root，因此内核授予 root 凭据并运行有效载荷。

`payload.c` 是纯可移植的 C 语言: `setgid(0); setuid(0); execve("/bin/sh", ...)`。nolibc 提供了 `_start`、系统调用机制以及特定架构的寄存器操作。

第二个变体 `exploit-passwd.c` 修改了 /etc/passwd 页缓存的四个字节，而不是 setuid 二进制文件的映像。它不需要嵌入有效载荷，可以在二进制变异路线被阻止的系统上工作，但其变现（达到提权目的）面要窄得多。

## 构建

默认 (宿主架构原生):

```sh
make
```

交叉编译到 aarch64 (或已安装交叉工具链的任何其他 Linux 架构):

```sh
make CC=aarch64-linux-gnu-gcc LD=aarch64-linux-gnu-ld
```

引入的 nolibc 支持的架构 (根据上游): x86_64, i386, arm, aarch64, riscv32/64, mips, ppc, s390x, loongarch, m68k, sh, sparc。nolibc 根据编译器的架构宏选择实现，因此只需选择正确的 `CC`/`LD` 即可。

构建要求:

* C 编译器 (`cc`, `gcc`, 或任何交叉变体)
* 支持 `ld -r -b binary` 的链接器 (binutils ld 和 lld 均支持)
* 提供 `linux/if_alg.h` 和 `<asm/unistd.h>` 的内核 UAPI 头文件 (Debian/Ubuntu: `linux-libc-dev`; 交叉变体: 通常由交叉工具链包引入)

没有外部库依赖。有效载荷是针对 nolibc 独立 (freestanding) 构建的；释放器仅为了 `fprintf` 和 `perror` 链接到宿主 libc。

## 架构选择

有三个微小的工具链特性在保持源代码可移植性和有效载荷小巧方面发挥了主要作用。

### nolibc

`nolibc/` 是内核的微型仅头文件 libc 替代品，源自 torvalds/linux 的 `tools/include/nolibc/`。它提供了 `_start`、可移植的 `syscall()` 宏以及内联系统调用包装器，特定架构的寄存器约定编码在 `nolibc/arch-*.h` 中。使用 `-nostdlib -static -ffreestanding -Inolibc` 构建有效载荷会生成一个微小的静态 ELF，直接调用内核，而不会引入 glibc 启动、TLS 初始化或 stack-canary 机制。结果：x86_64 上约为 1.7 KB，aarch64 上约为 2.0 KB。相比之下，相同的 `payload.c` 链接到 musl-static 约为 17 KB，链接到 glibc-static 约为 700 KB。

### 用于嵌入的 `ld -r -b binary`

Makefile 通过 `ld -r -b binary -o payload.o payload` 将构建的 `payload` ELF 转换为 `payload.o`。链接器将输入字节原样作为可重定位目标文件的数据段发出，并从输入文件名合成三个符号：

```
_binary_payload_start    第一个有效载荷字节的地址
_binary_payload_end      最后一个有效载荷字节之后的一个地址
_binary_payload_size     绝对符号，其值为以字节为单位的大小
```

`exploit.c` 将前两个声明为 `extern const unsigned char[]`，并将大小计算为 `_binary_payload_end - _binary_payload_start`。

### `-Wl,-N` 结合严格的 `max-page-size`

有效载荷使用 `-Wl,-N -Wl,-z,max-page-size=0x10` 进行静态链接。这会将 `.text`/`.rodata`/`.data` 折叠成一个具有 16 字节文件对齐的单一 LOAD 段，而不是默认的内核页面对齐的每段 4 KB。这会产生来自 `ld` 的 "RWX permissions" 警告，这仅是信息性的——有效载荷的运行时内存保护对其单一目的程序无关紧要。如果没有此标志，相同的代码在 x86_64 上链接约为 13 KB (主要是段间零填充)；使用它则为 1.7 KB。

## 变体和变现可行性

此仓库发布了两种漏洞利用变体，它们共享 AF_ALG/splice 页缓存变异原语，但以不同的方式变现（实现 root 执行）。它们的可靠性特征并不相同，在推理现实世界的威胁模型时，这种差异很重要。

### 二进制文件变异变体 (`exploit`)

使用嵌入的有效载荷字节修改目标 setuid 二进制文件的页缓存，然后 exec 该二进制文件。内核根据二进制文件未被触及的磁盘 setuid 位授予 root 凭据，加载损坏的内存映像，并运行有效载荷。

只要攻击者可以在系统上的任何 root-setuid 二进制文件上调用 `open(target, O_RDONLY)`，它就能工作。在限制读取目录后面的 setuid 二进制文件环境和无 setuid 的系统设计中，这种方法基本会失效。

### /etc/passwd UID 翻转变体 (`exploit-passwd`)

修改 /etc/passwd 页缓存的四个字节，将正在运行的用户的 UID 字段设置为 "0000"。/etc/passwd 在每个标准的 Linux 系统上都是全局可读的，因此*修改*是普遍适用的。将其转化为 root 执行依赖于某个 root 端的进程通过 getpwnam/getpwuid 解析用户，并根据解析出的 uid 行动而无需交叉验证。这样的使用者有很多；但其中许多防御性地根据内核中调用 uid 的视图或磁盘文件所有权进行交叉检查，从而打破了变现链。

#### 变现可行性矩阵

| 变现方式 | 是否需要 pre-root 设置 | 备注 |
|---|---|---|
| WSL2 会话生成 | 否 | WSL 每会话的 `setuid(getpwnam(default_user)->pw_uid)` 不做验证。完美工作。 |
| util-linux `su` | 否 | 宽松的调用者身份处理。 |
| shadow-utils `su` | 是 | `getpwuid(getuid())` 调用者身份检查失败，因为变异取消映射了真实 uid。 |
| sshd (默认 `StrictModes yes`) | 是 (禁用 StrictModes) | StrictModes 要求 home 目录归 root 或 `pw->pw_uid` 所有。变异使 pw_uid=0；磁盘所有者保持原样；不匹配导致拒绝身份验证。 |
| MTA 本地投递 (postfix, exim 等) | 视情况而定 | 取决于 MDA 的 home 权限验证。需要针对具体 MTA 测试。 |

#### `su` 失败后的利用转移 (Pivoting)

`exploit-passwd` 在变异后执行 `su <user>` 作为最简单的变现方式。这对 util-linux `su` 有效，但对 shadow-utils `su` 会因 "Cannot determine your user name." 失败。此时页面缓存变异仍然有效，可以转移到任何其他变现方式 (例如，使用通过 getpwnam 解析用户而不进行交叉检查的守护进程)。
测试完成后，请以 root 身份运行 `echo 3 > /proc/sys/vm/drop_caches` 以清除损坏的页面缓存。

## 受影响的内核

```
下限:    torvalds/linux 72548b093ee3   2017 年 8 月, v4.14
                                        (AF_ALG iov_iter 重构，引入了
                                         通过 splice 到 AEAD 散布列表
                                         来实现文件页面写入的原语)

上限:    torvalds/linux a664bf3d603d   2026 年 4 月, 主线
                                        (回退了 2017 年的 algif_aead
                                         原地优化；分离了源和目标散布列表
                                         以便页面缓存页面不能再作为
                                         可写的加密目标)
```

在此之间: 每一个没有向后移植该修复的主要发行版内核。
Ubuntu、RHEL、SUSE、Amazon Linux 和 Debian 在披露时都确认其自带的云镜像内核存在漏洞。发行版级别的向后移植修复在 2026 年 4 月 29 日左右与公开披露同时开始推出。要验证目标内核是否在受影响范围内，请检查 `a664bf3d603d` (或其特定于发行版的向后移植) 是否存在于内核的 git 日志或发行版的更改日志中。

## 许可证和致谢

CVE-2026-31431 的发现和最初披露: Theori / Xint。
官方分析报告: <https://copy.fail/>。

此 C 移植版: Tony Gies <tony.gies@crashunited.com>

`nolibc/`: 从 Linux 内核树引入，双重许可 LGPL-2.1-or-later 或 MIT (见 `nolibc/nolibc.h` 和各个文件的 SPDX 头文件)。

此仓库中的释放器和有效载荷源代码在与其依赖的 nolibc 树相同的双重 LGPL-2.1-or-later 或 MIT 条款下发布，以保持简单的许可证兼容性，方便任何将整个目录引入自己工作的人。

漏洞利用和有效载荷是出于安全研究和防御检测目的发布的。对您不拥有或未获得明确测试授权的系统使用是您自己的问题，与作者无关。