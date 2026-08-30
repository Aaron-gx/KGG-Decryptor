//! Offline decoders for the formats supported by the Go/Wails sibling project.
//!
//! The Tauri application keeps the format dispatch here so the UI only needs
//! one command.  All decoders operate on caller-owned bytes and return the
//! decrypted audio plus a detected output extension.

use aes::cipher::{BlockDecrypt, KeyInit};
use aes::Aes128;
use md5::{Digest, Md5};
use std::convert::TryInto;

const KGM_MAGIC: [u8; 16] = [
    0x7c, 0xd5, 0x32, 0xeb, 0x86, 0x02, 0x7f, 0x4b,
    0xa8, 0xaf, 0xa6, 0x8e, 0x0f, 0xff, 0x99, 0x14,
];
const VPR_MAGIC: [u8; 16] = [
    0x05, 0x28, 0xbc, 0x96, 0xe9, 0xe4, 0x5a, 0x43,
    0x91, 0xaa, 0xbd, 0xd0, 0x7a, 0xf5, 0x36, 0x31,
];
const KWM_MAGIC_1: &[u8; 16] = b"yeelion-kuwo-tme";
const KWM_MAGIC_2: &[u8; 16] = b"yeelion-kuwo\0\0\0\0";
const KWM_PREDEFINED_KEY: &[u8; 32] = b"MoOtOiTvINGwd2E6n0E1i7L5t2IoOoNk";
const NCM_MAGIC: &[u8; 8] = b"CTENFDAM";
const NCM_CORE_KEY: [u8; 16] = [
    0x68, 0x7a, 0x48, 0x52, 0x41, 0x6d, 0x73, 0x6f,
    0x35, 0x6b, 0x49, 0x6e, 0x62, 0x61, 0x78, 0x57,
];

pub(crate) fn decrypt_file(data: &[u8], filename: &str) -> Result<(Vec<u8>, String), String> {
    let ext = filename
        .rsplit_once('.')
        .map(|(_, e)| e.to_ascii_lowercase())
        .unwrap_or_default();

    match ext.as_str() {
        "kgg" => super::decrypt_kgg_bytes(data),
        "kgm" | "kgma" | "vpr" => decrypt_kgm(data, &ext),
        "ncm" => decrypt_ncm(data),
        "kwm" => decrypt_kwm(data),
        "qmc0" | "qmc2" | "qmc3" | "qmc4" | "qmc6" | "qmc8"
        | "qmcflac" | "qmcogg" | "tkm"
        // QQ Music has shipped a few aliases for the same QMC2 container.
        | "mflac" | "mflac0" | "mflac1"
        | "mgg" | "mgg0" | "mgg1" | "mggl" => decrypt_qmc(data),
        "krc" => Err("KRC 是歌词格式，请使用歌词转换入口".into()),
        _ => Err(format!("暂不支持 .{} 格式", if ext.is_empty() { "?" } else { &ext })),
    }
}

fn sniff_audio(data: &[u8]) -> Result<String, String> {
    let ext = super::sniff_ext(data);
    if ext != "bin" {
        return Ok(ext.to_string());
    }
    Err("解密后无法识别音频格式".into())
}

fn read_u32_le(data: &[u8], at: usize) -> Result<u32, String> {
    data.get(at..at + 4)
        .ok_or_else(|| "文件头长度不足".to_string())
        .and_then(|b| Ok(u32::from_le_bytes(b.try_into().unwrap())))
}

fn decrypt_kgm(data: &[u8], ext: &str) -> Result<(Vec<u8>, String), String> {
    if data.len() < 0x44 || (!data.starts_with(&KGM_MAGIC) && !data.starts_with(&VPR_MAGIC)) {
        return Err(format!("无效的 .{} 文件头", ext));
    }
    let audio_offset = read_u32_le(data, 0x10)? as usize;
    let version = read_u32_le(data, 0x14)?;
    if audio_offset > data.len() {
        return Err("KGM 音频偏移超出文件范围".into());
    }

    let mut audio = data[audio_offset..].to_vec();
    match version {
        3 => {
            // unlock-music only defines slot key 1 for the v3 cipher.
            let slot = read_u32_le(data, 0x18)?;
            if slot != 1 {
                return Err(format!("不支持的 KGM 加密槽位 {slot}"));
            }
            decrypt_kgm_v3(data, &mut audio);
        }
        5 => {
            let hash_len = read_u32_le(data, 0x44)? as usize;
            let hash_end = 0x48usize.checked_add(hash_len).ok_or("KGM audio hash 溢出")?;
            if hash_len == 0 || hash_end > data.len() {
                return Err("KGM audio hash 无效".into());
            }
            let hash = String::from_utf8_lossy(&data[0x48..hash_end]).trim_end_matches('\0').to_string();
            let db = super::find_db_path().ok_or("未找到 KGMusicV3.db（KGM v5 需要本地密钥库）")?;
            let raw_db = std::fs::read(&db).map_err(|e| format!("读取 KGMusicV3.db 失败: {e}"))?;
            let plain_db = super::decrypt_database(&raw_db);
            let keys = super::extract_ekey_map(&plain_db)?;
            let ekey = keys.get(&hash).ok_or_else(|| format!("数据库中没有 audio_hash={hash} 的 ekey"))?;
            let cipher = super::QmcCipher::new(super::derive_key(ekey)?)
                .ok_or("KGM v5 ekey 无法建立解密器")?;
            cipher.decrypt(&mut audio, 0);
        }
        other => return Err(format!("不支持的 KGM 加密版本 {other}")),
    }
    let format = sniff_audio(&audio)?;
    Ok((audio, format))
}

fn kugou_md5(input: &[u8]) -> [u8; 16] {
    let digest = Md5::digest(input);
    let mut out = [0u8; 16];
    for i in (0..16).step_by(2) {
        out[i] = digest[14 - i];
        out[i + 1] = digest[15 - i];
    }
    out
}

fn decrypt_kgm_v3(header: &[u8], audio: &mut [u8]) {
    let slot = kugou_md5(&[0x6c, 0x2c, 0x2f, 0x27]);
    let file = {
        let mut v = kugou_md5(&header[0x2c..0x3c]).to_vec();
        v.push(0x6b);
        v
    };
    for (i, byte) in audio.iter_mut().enumerate() {
        *byte ^= file[i % file.len()];
        let shifted = (*byte).wrapping_shl(4);
        *byte ^= shifted;
        *byte ^= slot[i % slot.len()];
        *byte ^= (i as u32 as u8)
            ^ ((i as u32 >> 8) as u8)
            ^ ((i as u32 >> 16) as u8)
            ^ ((i as u32 >> 24) as u8);
    }
}

fn decrypt_kwm(data: &[u8]) -> Result<(Vec<u8>, String), String> {
    if data.len() < 0x400 || (!data.starts_with(KWM_MAGIC_1) && !data.starts_with(KWM_MAGIC_2)) {
        return Err("无效的 KWM 文件头".into());
    }
    let key = &data[0x18..0x20];
    let key_int = u64::from_le_bytes(key.try_into().unwrap()).to_string();
    let mut key_text = String::with_capacity(32);
    if key_int.is_empty() {
        key_text.extend(std::iter::repeat('\0').take(32));
    } else {
        for i in 0..32 {
            key_text.push(key_int.as_bytes()[i % key_int.len()] as char);
        }
    }
    let mask: Vec<u8> = KWM_PREDEFINED_KEY
        .iter()
        .zip(key_text.as_bytes())
        .map(|(a, b)| a ^ b)
        .collect();
    let mut audio = data[0x400..].to_vec();
    for (i, byte) in audio.iter_mut().enumerate() {
        *byte ^= mask[i & 0x1f];
    }
    let format = sniff_audio(&audio)?;
    Ok((audio, format))
}

fn decrypt_ncm(data: &[u8]) -> Result<(Vec<u8>, String), String> {
    if data.len() < 14 || !data.starts_with(NCM_MAGIC) {
        return Err("无效的 NCM 文件头".into());
    }
    let mut offset = 10usize;
    let key_len = read_u32_le(data, offset)? as usize;
    offset = offset.checked_add(4).and_then(|v| v.checked_add(key_len)).ok_or("NCM key 长度溢出")?;
    if offset > data.len() || key_len == 0 {
        return Err("NCM key 数据不完整".into());
    }
    let mut key_blob = data[offset - key_len..offset].to_vec();
    for b in &mut key_blob { *b ^= 0x64; }
    let key_plain = aes_ecb_decrypt(&key_blob, &NCM_CORE_KEY)?;
    let key_plain = pkcs7_unpad(&key_plain)?;
    if key_plain.len() <= 17 {
        return Err("NCM 音频密钥无效".into());
    }
    let key_box = ncm_key_box(&key_plain[17..]);

    let meta_len = read_u32_le(data, offset)? as usize;
    offset = offset.checked_add(4).and_then(|v| v.checked_add(meta_len)).ok_or("NCM 元数据长度溢出")?;
    if offset > data.len() { return Err("NCM 元数据不完整".into()); }

    // Cover frame per the real NCM layout (unlock-music ncm.go, ncmdump.rs):
    // [5-byte gap][frameLen:4][imageLen:4][image][crc32:4][audio], where
    // frameLen counts the imageLen field + image bytes; the trailing crc32 is
    // skipped via the explicit +4. We must land exactly on the audio payload
    // or the keystream XOR desynchronizes.
    offset = offset.checked_add(5).ok_or("NCM 封面帧偏移溢出")?;
    let frame_len = read_u32_le(data, offset)? as usize;
    let audio_start = offset
        .checked_add(8)
        .and_then(|v| v.checked_add(frame_len))
        .ok_or("NCM 封面帧长度溢出")?;
    if audio_start > data.len() { return Err("NCM 封面帧不完整".into()); }
    let mut audio = data[audio_start..].to_vec();
    for (i, b) in audio.iter_mut().enumerate() { *b ^= key_box[i & 0xff]; }
    let format = sniff_audio(&audio)?;
    Ok((audio, format))
}

fn aes_ecb_decrypt(data: &[u8], key: &[u8; 16]) -> Result<Vec<u8>, String> {
    if data.is_empty() || data.len() % 16 != 0 { return Err("AES-ECB 数据长度无效".into()); }
    let cipher = Aes128::new_from_slice(key).map_err(|e| format!("AES key 无效: {e}"))?;
    let mut out = data.to_vec();
    for block_bytes in out.chunks_exact_mut(16) {
        let block = aes::cipher::generic_array::GenericArray::from_mut_slice(block_bytes);
        cipher.decrypt_block(block);
    }
    Ok(out)
}

fn pkcs7_unpad(data: &[u8]) -> Result<Vec<u8>, String> {
    let Some(&last) = data.last() else { return Err("PKCS#7 数据为空".into()); };
    let n = last as usize;
    if n == 0 || n > 16 || n > data.len() || !data[data.len() - n..].iter().all(|b| *b as usize == n) {
        return Err("PKCS#7 填充无效".into());
    }
    Ok(data[..data.len() - n].to_vec())
}

fn ncm_key_box(key: &[u8]) -> [u8; 256] {
    let mut boxv = [0u8; 256];
    for (i, b) in boxv.iter_mut().enumerate() { *b = i as u8; }
    let mut j = 0u8;
    for i in 0..256 {
        j = j.wrapping_add(boxv[i]).wrapping_add(key[i % key.len()]);
        boxv.swap(i, j as usize);
    }
    let mut out = [0u8; 256];
    for i in 0..256 {
        let si = boxv[(i + 1) & 0xff];
        let sj = boxv[(i + 1 + si as usize) & 0xff];
        out[i] = boxv[(si as usize + sj as usize) & 0xff];
    }
    out
}

fn decrypt_qmc(data: &[u8]) -> Result<(Vec<u8>, String), String> {
    if data.len() < 4 { return Err("QMC 文件太短".into()); }
    if data.len() >= 16 && data.ends_with(b"musicex\0") {
        let trailer = &data[data.len() - 16..];
        let footer_len = u32::from_le_bytes(trailer[..4].try_into().unwrap()) as usize;
        let version = u32::from_le_bytes(trailer[4..8].try_into().unwrap());
        if footer_len != 0xc0 || version != 1 || footer_len >= data.len() {
            return Err("musicex 尾部版本或长度无效".into());
        }
        return Err("新版 musicex 文件需要 QQ 音乐会话取钥；当前 Tauri 版本暂不联网取钥".into());
    }
    let last4 = &data[data.len() - 4..];
    let (audio_len, cipher) = if last4 == b"STag" {
        return Err("STag 文件不包含可离线使用的密钥".into());
    } else if last4 == b"QTag" {
            if data.len() < 8 { return Err("QTag 文件太短".into()); }
            let key_len = u32::from_be_bytes(data[data.len() - 8..data.len() - 4].try_into().unwrap()) as usize;
            let audio_len = data.len().checked_sub(8 + key_len).ok_or("QTag 密钥长度无效")?;
            let raw = &data[audio_len..data.len() - 8];
            let key_end = raw.iter().position(|b| *b == b',').ok_or("QTag ekey 不完整")?;
            let cipher = super::QmcCipher::new(super::derive_key(std::str::from_utf8(&raw[..key_end]).map_err(|_| "QTag ekey 不是文本")?)?)
                .ok_or("QTag ekey 无效")?;
            (audio_len, cipher)
    } else {
            // Legacy ekey tail: [ekey text][u32 LE length].  unlock-music
            // accepts lengths up to 0xFFFF and trims trailing NUL padding;
            // some QQ Music builds pad the ekey field to a fixed size.
            let key_len = u32::from_le_bytes(last4.try_into().unwrap()) as usize;
            if key_len > 0 && key_len <= 0xFFFF {
                let audio_len = data.len().checked_sub(4 + key_len).ok_or("QMC 密钥长度无效")?;
                let raw = &data[audio_len..data.len() - 4];
                let raw_text = std::str::from_utf8(raw)
                    .map_err(|_| "QMC ekey 不是文本")?
                    .trim_end_matches('\0');
                let cipher = super::QmcCipher::new(super::derive_key(raw_text)?)
                    .ok_or("QMC ekey 无效")?;
                (audio_len, cipher)
            } else {
                (data.len(), super::QmcCipher::static_cipher())
            }
    };
    let mut audio = data[..audio_len].to_vec();
    cipher.decrypt(&mut audio, 0);
    let format = sniff_audio(&audio)?;
    Ok((audio, format))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qmc_static_cipher_is_reversible() {
        let plain = b"ID3 synthetic qmc payload".to_vec();
        let mut encrypted = plain.clone();
        let cipher = super::super::QmcCipher::static_cipher();
        cipher.decrypt(&mut encrypted, 0);
        cipher.decrypt(&mut encrypted, 0);
        assert_eq!(encrypted, plain);
    }

    #[test]
    fn kwm_decoder_round_trip() {
        let mut data = vec![0u8; 0x400];
        data[..16].copy_from_slice(KWM_MAGIC_1);
        data[0x18..0x20].copy_from_slice(&12345678u64.to_le_bytes());
        let plain = b"ID3 synthetic kwm payload";
        let key_int = 12345678u64.to_string();
        let mut key_text = Vec::with_capacity(32);
        for i in 0..32 { key_text.push(key_int.as_bytes()[i % key_int.len()]); }
        let mask: Vec<u8> = KWM_PREDEFINED_KEY.iter().zip(key_text).map(|(a, b)| a ^ b).collect();
        let mut enc = plain.to_vec();
        for (i, b) in enc.iter_mut().enumerate() { *b ^= mask[i & 0x1f]; }
        data.extend(enc);
        let (got, ext) = decrypt_kwm(&data).unwrap();
        assert_eq!(got, plain);
        assert_eq!(ext, "mp3");
    }

    #[test]
    fn musicex_footer_is_rejected_without_network_key() {
        let mut data = vec![0u8; 32];
        data.extend(vec![0u8; 0xc0]);
        let at = data.len() - 16;
        data[at..at + 4].copy_from_slice(&(0xc0u32).to_le_bytes());
        data[at + 4..at + 8].copy_from_slice(&1u32.to_le_bytes());
        data[at + 8..].copy_from_slice(b"musicex\0");
        let err = decrypt_qmc(&data).unwrap_err();
        assert!(err.contains("musicex"));
    }

    // ---- NCM: build a file with the real container layout and decrypt it ----
    // Layout (unlock-music ncm.go / ncmdump.rs):
    //   CTENFDAM(8) gap(2) keyLen(4) key metaLen(4) meta gap(5)
    //   frameLen(4) imageLen(4) image crc32(4) audio
    //   frameLen = 4 + imageLen; audio starts at frameLenField + 8 + frameLen.

    fn ncm_key_box(key: &[u8]) -> [u8; 256] {
        let mut boxv = [0u8; 256];
        for (i, b) in boxv.iter_mut().enumerate() { *b = i as u8; }
        let mut j = 0u8;
        for i in 0..256 {
            j = j.wrapping_add(boxv[i]).wrapping_add(key[i % key.len()]);
            boxv.swap(i, j as usize);
        }
        let mut out = [0u8; 256];
        for i in 0..256 {
            let si = boxv[(i + 1) & 0xff];
            let sj = boxv[(i + 1 + si as usize) & 0xff];
            out[i] = boxv[(si as usize + sj as usize) & 0xff];
        }
        out
    }

    fn aes_ecb_encrypt(data: &[u8], key: &[u8; 16]) -> Vec<u8> {
        use aes::cipher::{BlockEncrypt, KeyInit};
        let cipher = Aes128::new_from_slice(key).unwrap();
        data.chunks(16).flat_map(|ch| {
            let mut block = [0u8; 16];
            block[..ch.len()].copy_from_slice(ch);
            cipher.encrypt_block(aes::cipher::generic_array::GenericArray::from_mut_slice(&mut block));
            block.to_vec()
        }).collect()
    }

    fn build_ncm() -> Vec<u8> {
        let rc4_key: &[u8] = b"#14ljk_!\\]&0U<'(netease";
        let mut key_plain: Vec<u8> = b"neteasecloudmusic".to_vec();
        key_plain.extend_from_slice(rc4_key);
        let pad = 16 - key_plain.len() % 16;
        key_plain.extend(std::iter::repeat(pad as u8).take(pad));
        let mut key_blob = aes_ecb_encrypt(&key_plain, &NCM_CORE_KEY);
        for b in &mut key_blob { *b ^= 0x64; }

        let boxv = ncm_key_box(rc4_key);
        let plain: Vec<u8> = {
            let mut v = b"fLaC\x00\x00\x00\x22".to_vec();
            v.extend((0..512u32).map(|i| i as u8).collect::<Vec<_>>());
            v
        };
        let audio: Vec<u8> = plain.iter().enumerate().map(|(i, b)| b ^ boxv[i & 0xff]).collect();

        let image = [0xAAu8, 1, 2, 3, 4, 5, 6, 7, 8, 9];
        let mut out = Vec::new();
        out.extend_from_slice(b"CTENFDAM");
        out.extend_from_slice(&[0u8, 0]);
        out.extend_from_slice(&(key_blob.len() as u32).to_le_bytes());
        out.extend_from_slice(&key_blob);
        out.extend_from_slice(&0u32.to_le_bytes()); // no metadata
        out.extend_from_slice(&[0u8; 5]); // 5-byte gap before the cover frame
        out.extend_from_slice(&((image.len() as u32 + 4) as u32).to_le_bytes()); // frameLen
        out.extend_from_slice(&(image.len() as u32).to_le_bytes());
        out.extend_from_slice(&image);
        out.extend_from_slice(&0x12345678u32.to_le_bytes()); // crc32 after the image
        out.extend_from_slice(&audio);
        out
    }

    #[test]
    fn ncm_reference_layout_round_trip() {
        let file = build_ncm();
        let (audio, ext) = decrypt_ncm(&file).unwrap();
        assert_eq!(&audio[..4], b"fLaC", "audio keystream is misaligned");
        assert_eq!(ext, "flac");
    }

    #[test]
    fn ncm_truncated_file_is_rejected() {
        let file = build_ncm();
        // cut inside the key blob -> must error cleanly, not panic
        let err = decrypt_ncm(&file[..30]).unwrap_err();
        assert!(!err.is_empty());
    }

    // ---- KGM v3: the XOR chain is decrypted in the order
    // fileKey / b<<4 / slot / offset-collapse, so encryption must run the
    // inverse chain (`b ^= b<<4` is not an involution). ----

    #[test]
    fn kgm_v3_round_trip() {
        let mut file = vec![0u8; 0x40];
        file[..16].copy_from_slice(&KGM_MAGIC);
        file[0x10..0x14].copy_from_slice(&0x40u32.to_le_bytes());
        file[0x14..0x18].copy_from_slice(&3u32.to_le_bytes());
        file[0x18..0x1c].copy_from_slice(&1u32.to_le_bytes()); // crypto slot
        for (i, b) in [0x11u8, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88,
                       0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x11, 0x22].iter().enumerate() {
            file[0x2c + i] = *b;
        }

        let slot = kugou_md5(&[0x6c, 0x2c, 0x2f, 0x27]);
        let mut file_key = kugou_md5(&file[0x2c..0x3c]).to_vec();
        file_key.push(0x6b);

        let plain: Vec<u8> = {
            let mut v = b"fLaC".to_vec();
            v.extend((0..512u32).map(|i| i as u8).collect::<Vec<_>>());
            v
        };
        let mut enc = plain.clone();
        for (i, byte) in enc.iter_mut().enumerate() {
            *byte ^= (i as u32 as u8)
                ^ ((i as u32 >> 8) as u8)
                ^ ((i as u32 >> 16) as u8)
                ^ ((i as u32 >> 24) as u8);
            *byte ^= slot[i % slot.len()];
            // inverse of b ^= b<<4: low nibble unchanged, high nibble XOR low
            let lo = *byte & 0x0f;
            let hi = ((*byte >> 4) ^ lo) & 0x0f;
            *byte = (hi << 4) | lo;
            *byte ^= file_key[i % file_key.len()];
        }
        file.extend_from_slice(&enc);

        let (audio, ext) = decrypt_file(&file, "song.kgm").unwrap();
        assert_eq!(audio, plain);
        assert_eq!(ext, "flac");
    }

    #[test]
    fn kgm_v3_unknown_crypto_slot_is_rejected() {
        let mut file = vec![0u8; 0x48]; // >= 0x44 so the header guard passes
        file[..16].copy_from_slice(&KGM_MAGIC);
        file[0x10..0x14].copy_from_slice(&0x40u32.to_le_bytes());
        file[0x14..0x18].copy_from_slice(&3u32.to_le_bytes());
        file[0x18..0x1c].copy_from_slice(&7u32.to_le_bytes()); // unknown slot
        let err = decrypt_file(&file, "song.kgm").unwrap_err();
        assert!(err.contains("槽位"));
    }
}
