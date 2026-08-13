# KGG Decryptor

KuGou KGG 加密音乐文件解密转换工具，基于 Tauri 2 构建。支持手动解密和自动监控酷狗下载目录，下载完成后自动转换为 MP3 / FLAC / OGG。

## Important / 使用前提（必读）

**本工具不能凭空破解 KGG 加密。** 它只是一个格式转换工具，工作前提是：

1. **你必须是酷狗会员**，并且已经在酷狗客户端中成功下载过歌曲
2. 下载过程中，酷狗会在本地数据库 `KGMusicV3.db` 中写入每首歌的解密密钥（eKey）
3. 本工具读取这个数据库中的密钥，对已下载的 KGG 文件进行解密
4. 如果数据库中没有对应歌曲的密钥，解密会失败

简单说：**酷狗能播的歌，本工具才能转。酷狗没有下载过的歌，本工具转不了。**

这跟网上流传的 NCM/QMC 解密工具原理一样——都是读取本地已有的密钥，不是破解加密算法本身。如果你不是酷狗会员、或者没有下载过该歌曲，这个工具对你没有用。

## Features / 功能

- **手动解密** - 拖拽 KGG 文件，一键转换为可播放格式
- **自动监控** - 开启后自动监听酷狗下载目录，新文件写入即解密
- **歌词转换** - 批量将酷狗 KRC 加密歌词转换为标准 LRC 格式
- **路径自定义** - 监听目录和输出目录均可自由设置，支持浏览选择
- **歌曲库浏览** - 读取酷狗数据库，查看已下载歌曲列表及密钥状态
- **全本地处理** - 所有解密在本地完成，不会上传任何文件

## KRC Lyrics / 歌词转换说明

KRC 是酷狗的加密歌词格式，位于 `D:\KuGou\Lyric\` 目录下。与 KGG 音乐文件不同，**KRC 歌词的解密不需要数据库密钥**：

1. KRC 文件以 `krc1` 魔术头开头
2. 使用固定 16 字节 XOR 密钥解密
3. 解密后的数据是标准 zlib 压缩流
4. 解压后即为 UTF-8 编码的 LRC 文本

因此 KRC 歌词转换不需要酷狗会员或数据库，任何 KRC 文件都可以直接转换。

## How It Works / 工作原理

```
酷狗客户端下载歌曲
       |
       v
KGG 加密文件 + KGMusicV3.db（含 eKey 密钥）
       |
       v
本工具读取数据库 -> 解密数据库 AES 层 -> 提取 eKey
       |
       v
eKey 经 TEA + Base64 多层推导 -> 得到原始密钥
       |
       v
根据密钥长度选择 MapCipher / RC4Cipher -> 解密音频
       |
       v
输出 MP3 / FLAC / OGG
```

关键技术点：

- KGG 文件头包含 KGM Magic、音频偏移量、音频哈希
- KGMusicV3.db 数据库本身经过 AES-128-CBC 分页加密，需要逐页解密
- eKey 经过 TEA（Tencent Encryption Algorithm）和 Base64 多层封装
- 解密后的密钥长度决定使用 MapCipher（短密钥）还是 RC4Cipher（长密钥）
- 输出格式通过文件头魔术字节（ID3 / fLaC / OggS）自动判断

## Build / 构建

### 环境要求

- [Node.js](https://nodejs.org/) 18+
- [Rust](https://rustup.rs/) (stable)
- C/C++ 编译器（MSVC 或 MinGW）

### 编译步骤

```bash
cd tauri-app
npm install
npx tauri build
```

生成的可执行文件位于 `tauri-app/src-tauri/target/release/`。

### 开发模式

```bash
cd tauri-app
npm install
npx tauri dev
```

## Tech Stack / 技术栈

- **Tauri 2** - 桌面应用框架
- **Rust** - 后端解密逻辑（AES-CBC / TEA / QMC Map & RC4）
- **notify** - 文件系统监听
- **rusqlite** - SQLite 数据库读取
- **flate2** - KRC 歌词 zlib 解压

## Project Structure / 项目结构

```
tauri-app/
├── src/
│   └── index.html          # 前端界面
└── src-tauri/
    ├── Cargo.toml
    ├── tauri.conf.json
    ├── capabilities/
    │   └── default.json     # 权限配置
    ├── icons/
    └── src/
        ├── lib.rs           # 解密逻辑 + Tauri 命令
        └── main.rs          # 入口点
```

## Limitations / 已知限制

- 仅支持酷狗 KGG 格式（crypto version 5），不支持其他平台加密格式
- 必须有对应的本地数据库密钥，无密钥无法解密
- 如果酷狗更新了加密方案，本工具可能需要相应更新
- 目前仅支持 Windows

## License

MIT
