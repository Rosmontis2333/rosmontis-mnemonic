# Rosmontis 助记词命令行程序

支持 64 位 macOS（Apple Silicon / Intel）、Windows 10/11（x64 / ARM64）、Linux（x64 / ARM64）。无需 Python。无参数时使用默认配置；任意参数触发交互设置。命令行参数内容不会作为秘密，也不会被解析为参数值。仍不允许通过环境变量、文件或管道传入秘密。

## 运行

- macOS/Linux：在终端运行 `./rosmontis-mnemonic`。
- Windows：在 Windows Terminal、PowerShell 或 cmd 中运行 `.\rosmontis-mnemonic.exe`。需要真正的 Windows 控制台，不能重定向输入输出；不支持旧版 Windows 或仅模拟 POSIX PTY 的终端。
- 输入一次字符串后立即开始计算；输入时回显，按回车后立即清除整个替代屏幕，再开始计算。显示 Argon2 每轮完成的轮数、百分比和耗时。助记词在替代屏幕中显示，回车清屏退出。
- Linux 锁页限额需要至少约 8 GiB 加 64 MiB。用 `ulimit -l` 查看当前软限额（KiB）；若硬限额允许，可在启动程序的同一 shell 设置 `ulimit -l 8454144`。若提示不允许，需要管理员配置对应用户的 memlock 限额并重新登录。本程序不会修改系统配置或自动降级。
- Windows 会申请增大本进程的工作集，再通过 VirtualLock 锁页；权限、可用物理内存或系统策略不允许时停止，不读取秘密。

## 精确算法

输入按 UTF-8 编码，不去除空格、不进行 Unicode 归一化。Windows 使用 ReadConsoleW 读取 UTF-16，再在锁定缓冲区中转换为 UTF-8。只移除交互回车产生的行结束符。

原始字节 SHA-512 233 轮 → SHA-256 233 轮 → Argon2d v1.3（m=8388608 KiB，t=32，lanes=8，threads=8，输出 32 字节，盐为 SHA256("rosmontis") 的 32 字节原始摘要）→ SHA-512 233 轮 → SHA-256 233 轮 → BIP39 英文 24 词（包含校验和）。

Argon2 内存块按算法要求向下对齐到 lanes×4；仍传入原始 m 参数，工作区预留完整 8 GiB。这与 argon2-cffi 的结果相同。三个平台共用同一份 SHA-2、Argon2 和词表，不使用平台特有哈希实现。

## 本地构建

安装 CMake 3.20+ 和 C11 编译器；Windows 可使用 Visual Studio 2022 的“使用 C++ 的桌面开发”组件。代码不需要另外安装 Argon2/OpenSSL/Python。

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release
ctest --test-dir build -C Release --output-on-failure
```

macOS Intel + Apple Silicon 通用构建：

```sh
cmake -S . -B build-universal -DCMAKE_BUILD_TYPE=Release '-DCMAKE_OSX_ARCHITECTURES=arm64;x86_64'
cmake --build build-universal
```

Windows 多配置生成器的程序位于 `build/Release/rosmontis-mnemonic.exe`；其他平台通常位于 `build/rosmontis-mnemonic`。

发行包中包含 `rosmontis-selftest`（Windows 为 `.exe`），可先运行公开测试向量；该测试不读取秘密，也不执行完整 8 GiB 计算，但同样要求锁页权限。

也可以安装 Zig，执行 `./cross-build.sh x86_64-windows-gnu`、`./cross-build.sh aarch64-windows-gnu`、`./cross-build.sh x86_64-linux-musl` 或 `./cross-build.sh aarch64-linux-musl`。环境变量 ZIG 可指定编译器路径、DEST 可指定产物目录。Linux 交叉编译产物静态链接 musl。推荐使用 64 位环境。

## 安全防护与边界

- POSIX：mmap+mlock 锁定输入、Argon2 工作区、自定义 pthread 计算栈。Linux 另设 MADV_DONTDUMP、PR_SET_DUMPABLE=0；POSIX 检查 RLIMIT_CORE=0 是否成功。
- Windows：VirtualAlloc+VirtualLock 锁定输入和工作区。每个计算线程在预提交的 fiber 栈中运行，先锁定实际已提交的栈区，再执行哈希；完成后切回监督栈，覆写整个计算栈，再解锁并删除 fiber。若栈区过小或锁定失败，线程创建返回错误。
- Windows 使用 SetErrorMode 的 SEM_NOGPFAULTERRORBOX 抑制本进程的正常 WER 路径。这不等于能阻止管理员配置的 LocalDumps、调试器、外部转储工具或整机内存转储。
- 正常释放前用 volatile 覆写（Windows 使用 SecureZeroMemory），然后解锁、释放。为 BIP39 seed 派生，程序在锁定的计算栈上临时构造固定大小的助记词字符串，使用后立即覆写；seed、私钥、链码、HMAC 中间值同样清零。secp256k1 上下文使用锁定的预分配内存，随机盲化后使用，释放前清零。关闭 stdout/stderr 用户态缓冲，不写日志或秘密文件。
- Ctrl+C / 终止时尽力恢复终端；进程终止前，敏感工作区保持锁定。强制杀进程或系统崩溃无法保证执行所有覆写，不能宣称物理内存、寄存器、操作系统/运行库内部对象中绝对不存在短暂副本。
- 本程序无法阻止内核、管理员、恶意软件、终端会话录制、录屏或系统休眠镜像。不能追溯清除旧版本的交换页、崩溃文件和备份。替代屏幕也不是对所有终端的录制保证。

API 文档：[Apple mlock](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/mlock.2.html)、[Windows VirtualLock](https://learn.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtuallock)、[Windows CreateFiberEx](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createfiberex)、[Windows SetErrorMode](https://learn.microsoft.com/en-gb/windows/win32/api/errhandlingapi/nf-errhandlingapi-seterrormode)。

## 验证范围

此前版本已在 macOS Apple Silicon 上通过 536 个 SHA-256/512 对照向量、低内存 256 轮助记词对照及进度、内存清理测试。本次更新取消二次确认，将正式内存参数改为 8 GiB，并将并行度改为 8；验证了单次输入后开始计算的交互流程、低内存 256 轮结果与 CTest。未执行正式 8 GiB 锁定和完整派生。

v1.0.1 已通过 GitHub Actions Windows x64、Linux x64、macOS 的原生构建和 CTest（含八线程 Argon2d、锁定计算栈、哈希向量和清理测试）。Windows/Linux 下载包为 Zig 交叉编译产物，未直接在 CI 运行这些下载文件；Windows ARM64、Linux ARM64 和 macOS Intel 切片尚未实机验证。未执行完整 8 GiB×32 轮计算。

v1.0.2 改为输入回显、回车后清屏；保留锁页、单次输入、计算参数及助记词输出。

v1.0.1 修复 Windows 把 VirtualQuery 的单个 4 KiB 区域误认为完整 fiber 栈的问题：现在识别整个栈分配范围，预提交并锁定全部可用计算栈，保留底部不可访问页；真正锁定失败时显示失败 API 和 Windows 错误码，仍然停止计算。

Argon2 上游许可证见 `argon2/LICENSE`。修改仅涉及进度回调与线程适配，保留原算法。


v1.0.3 将正式 Argon2d 迭代次数改为 32，保持 8 GiB 和并行度 8。历史版本的 256 轮测试记录仅描述当时验证；当前版本通过低内存 32 轮计算对照、完整进度及输入回显/清屏测试。内存和迭代参数改变会改变同一输入生成的助记词。


## v1.1.0：EVM 地址和 zpub

助记词之后显示：

- EVM 第一个地址：`m/44'/60'/0'/0/0`，secp256k1 非压缩公钥的 Keccak-256 后 20 字节，使用 EIP-55 校验和显示。不是 SHA3-256。
- Bitcoin 主网 BIP84 账户 0 的扩展公钥 zpub：`m/84'/0'/0'`，版本 `0x04b24746`，Base58Check 编码。
- BIP39 passphrase 固定为空。输出页面标明路径与 passphrase 约定；钱包导入时应使用同样的设置。

地址由最终显示的英文助记词按 BIP39（PBKDF2-HMAC-SHA512、2048 轮）生成 seed，再通过 BIP32 派生。此功能不修改助记词算法和 Argon2 参数。程序不显示 seed、私钥、zprv。

新增验证：BIP84 官方 12 词向量、EVM 校验和地址向量，以及 ethers 与 @scure/bip32 独立生成的 3 组 24 词向量。完整交互流程在低内存测试配置下核对助记词、EVM 地址和 zpub。

参考：[BIP39](https://github.com/bitcoin/bips/blob/master/bip-0039.mediawiki)、[BIP32](https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki)、[BIP84 含官方测试向量](https://github.com/bitcoin/bips/blob/master/bip-0084.mediawiki)、[Ethereum 地址](https://ethereum.org/developers/docs/accounts/)。椭圆曲线运算使用内置 libsecp256k1 v0.8.0；来源与许可证见 `vendor/README.md`。


## v1.2.0：交互配置

`rosmontis-mnemonic` 无参数启动默认使用 8 GiB、32 次、并行度 8。
`rosmontis-mnemonic config` 或任何其他参数组合会依次询问内存（GB 按 GiB=1024³ 字节）、迭代次数、并行度。参数内容只作开关，不解析其值；不要把秘密放进启动命令。每项回车使用默认值。

内存支持小数，最大 4095 GiB，转换为 KiB 时向下取整；实际 KiB 参数在运行时显示。迭代为 1～4294967295 的整数，并行为 1～256 的整数（通道数和线程数相同），内存不得少于并行度×8 KiB。极大的配置可能耗时极长或因系统资源不足停止。锁定失败仍然停止、不降级。

设置仅用于本次进程，不保存配置。选择完成后才初始化受保护的计算环境和读取秘密；设置页面使用公开数字输入。复现钱包必须使用相同内存 KiB、迭代次数、并行度及输入字符串。参数不同，助记词、地址和 zpub 都会改变。
