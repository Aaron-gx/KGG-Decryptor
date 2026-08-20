# KGG Decryptor

KGG Decryptor 是一个基于 Tauri 2 的酷狗本地音乐解密转换工具。它可以读取本机酷狗客户端已下载歌曲对应的本地密钥，将 KGG 音乐文件转换为 MP3 / FLAC / OGG，并支持 KRC 歌词批量转换为标准 LRC。

> 本项目只处理你本机已经具备播放和下载条件的文件，不提供绕过会员、绕过授权或在线破解能力。

## Preview

> 截图占位：后续将桌面端主界面截图保存为 `docs/screenshots/app-main.png` 即可在这里显示。

![KGG Decryptor desktop preview](docs/screenshots/app-main.png)

## Features

- 手动解密：拖拽或选择 KGG 文件，一键转换为可播放音频格式。
- 自动监控：监听酷狗下载目录，新 KGG 文件下载完成后自动解密。
- 批量解密：选择目录后批量处理其中的 KGG 文件。
- 歌词转换：将酷狗 KRC 加密歌词批量转换为标准 LRC。
- 歌曲库浏览：读取酷狗本地数据库，查看已下载歌曲和密钥状态。
- 本地处理：解密、转换和数据库读取均在本机完成。

## Important

KGG 音乐转换依赖酷狗客户端写入本地数据库的解密密钥，因此使用前需要满足以下条件：

1. 你是酷狗会员，且已在酷狗客户端中成功下载过目标歌曲。
2. 酷狗客户端已在本地 `KGMusicV3.db` 数据库中写入该歌曲对应的 `eKey`。
3. 本工具能读取到本机的酷狗数据库和目标 KGG 文件。

简单说：酷狗客户端已经能在本机播放、且已经下载过的歌，本工具才有机会转换；数据库中没有对应密钥的文件无法解密。

KRC 歌词转换不依赖数据库密钥。KRC 文件以 `krc1` 魔术头开头，经过固定 XOR 密钥解密和 zlib 解压后，可转换为 UTF-8 编码的 LRC 文本。

## How It Works

```text
酷狗客户端下载歌曲
       |
       v
KGG 加密文件 + KGMusicV3.db（含 eKey 密钥）
       |
       v
读取并解密本地数据库 -> 提取歌曲 eKey
       |
       v
eKey 经 TEA + Base64 多层推导 -> 得到原始密钥
       |
       v
根据密钥类型选择 MapCipher / RC4Cipher -> 解密音频数据
       |
       v
根据文件头识别格式 -> 输出 MP3 / FLAC / OGG
```

关键技术点：

- KGG 文件头包含 KGM Magic、音频偏移量和音频哈希。
- `KGMusicV3.db` 数据库经过 AES-128-CBC 分页加密，需要先解密再查询。
- `eKey` 经过 TEA 和 Base64 多层封装，需要推导出原始密钥。
- 解密算法根据密钥长度选择 MapCipher 或 RC4Cipher。
- 输出格式通过音频文件头魔术字节自动判断，例如 `ID3`、`fLaC`、`OggS`。

## Tech Stack

- Tauri 2：桌面应用框架。
- Rust：后端解密、文件监听、数据库读取和批量转换逻辑。
- Vanilla HTML/CSS/JavaScript：前端单页界面。
- rusqlite：读取酷狗 SQLite 数据库。
- notify：监听文件系统变更。
- flate2：解压 KRC 歌词内容。

## Project Structure

```text
.
├── README.md                    # 项目说明和使用文档
├── LICENSE
├── docs/
│   └── screenshots/
│       └── README.md           # README 截图放置说明
└── tauri-app/
    ├── package.json            # Tauri CLI 脚本和前端侧依赖
    ├── package-lock.json
    ├── src/
    │   └── index.html          # 桌面端单页界面
    └── src-tauri/
        ├── Cargo.toml          # Rust 依赖和构建配置
        ├── tauri.conf.json     # Tauri 应用配置
        ├── build.rs
        ├── capabilities/
        │   └── default.json    # Tauri 权限配置
        ├── icons/              # 应用图标
        └── src/
            ├── lib.rs          # 解密、歌词转换、监听和 Tauri 命令
            └── main.rs         # 应用入口
```

项目中的 `node_modules/`、`dist/`、`src-tauri/target/`、本地数据库和音频文件都属于本地依赖或构建/个人数据，已通过 `.gitignore` 排除。

## Development

### Requirements

- Node.js 18+
- Rust stable
- Windows C/C++ 编译环境（MSVC 或 MinGW）

### Install

```bash
cd tauri-app
npm install
```

### Run In Development

```bash
cd tauri-app
npm run dev
```

### Build Installer

```bash
cd tauri-app
npm run build
```

构建产物位于 `tauri-app/src-tauri/target/release/`，安装包由 Tauri 输出到对应的 bundle 目录。

## Usage

1. 确认酷狗客户端已下载目标歌曲，并且本机数据库中存在对应密钥。
2. 启动应用后，可拖拽 KGG 文件到窗口中进行单文件转换。
3. 如需自动转换，设置监听目录和输出目录后启用“自动监控”。
4. 如需处理歌词，选择 KRC 歌词目录和输出目录后执行批量转换。

## Limitations

- 当前主要面向 Windows 环境。
- 仅支持已实现的酷狗 KGG / KRC 格式。
- KGG 转换必须依赖本地数据库中的对应密钥。
- 如果酷狗更新加密方案，相关解析逻辑可能需要同步调整。

## License

MIT
