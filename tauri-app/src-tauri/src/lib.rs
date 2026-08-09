use serde::Serialize;
use aes::Aes128;
use cbc::Decryptor as CbcDec;
use cipher::{block_padding::NoPadding, BlockDecryptMut, KeyIvInit};
use md5::{Md5, Digest};
use rusqlite::Connection;
use base64::Engine;
use std::collections::HashMap;
use notify::{Watcher, RecursiveMode, Event, EventKind};
use std::path::Path;
use tauri::Emitter;

const PAGE_SIZE: usize = 0x400;
const SQLITE_HEADER: &[u8] = b"SQLite format 3\x00";
const TEA_DELTA: u32 = 0x9E3779B9;
const KGM_MAGIC: [u8; 16] = [
    0x7C, 0xD5, 0x32, 0xEB, 0x86, 0x02, 0x7F, 0x4B,
    0xA8, 0xAF, 0xA6, 0x8E, 0x0F, 0xFF, 0x99, 0x14,
];
const DEFAULT_MASTER_KEY: [u8; 24] = [
    0x1D, 0x61, 0x31, 0x45, 0xB2, 0x47, 0xBF, 0x7F,
    0x3D, 0x18, 0x96, 0x72, 0x14, 0x4F, 0xE4, 0xBF,
    0x00, 0x00, 0x00, 0x00, 0x73, 0x41, 0x6C, 0x54,
];

type Aes128CbcDec = CbcDec<Aes128>;

fn u32(v: u64) -> u32 { (v & 0xFFFFFFFF) as u32 }

fn aes_cbc_decrypt(data: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let cipher = Aes128CbcDec::new(key.into(), iv.into());
    let mut buf = data.to_vec();
    let len = cipher.decrypt_padded_mut::<NoPadding>(&mut buf).unwrap_or(&[]).len();
    buf.truncate(len.max(data.len()));
    buf
}

fn md5(data: &[u8]) -> [u8; 16] { Md5::digest(data).into() }

fn derive_iv_seed(seed: u32) -> u32 {
    let left = u32(seed as u64 * 0x9EF4);
    let right = u32((seed / 0xCE26) as u64 * 0x7FFFFF07);
    let value = u32(left as u64 - right as u64);
    if value & 0x80000000 == 0 { value } else { u32(value as u64 + 0x7FFFFF07) }
}

fn derive_page_iv(page: u32) -> [u8; 16] {
    let mut iv_buf = [0u8; 16];
    let mut p = page + 1;
    for i in (0..16).step_by(4) {
        p = derive_iv_seed(p);
        iv_buf[i..i+4].copy_from_slice(&p.to_le_bytes());
    }
    md5(&iv_buf)
}

fn derive_page_key(page: u32) -> [u8; 16] {
    let mut mk = DEFAULT_MASTER_KEY.to_vec();
    mk[0x10..0x14].copy_from_slice(&page.to_le_bytes());
    md5(&mk)
}

fn decrypt_database(data: &[u8]) -> Vec<u8> {
    if data.starts_with(SQLITE_HEADER) { return data.to_vec(); }
    let n_pages = data.len() / PAGE_SIZE;
    let mut buf = data.to_vec();
    decrypt_page1(&mut buf);
    for pg in 2..=n_pages as u32 {
        let off = ((pg - 1) as usize) * PAGE_SIZE;
        let key = derive_page_key(pg);
        let iv = derive_page_iv(pg);
        let chunk: &mut [u8] = &mut buf[off..off + PAGE_SIZE];
        let dec = aes_cbc_decrypt(chunk, &key, &iv);
        chunk.copy_from_slice(&dec);
    }
    buf
}

fn decrypt_page1(buf: &mut [u8]) {
    let o10 = u32::from_le_bytes(buf[0x10..0x14].try_into().unwrap());
    let o14 = u32::from_le_bytes(buf[0x14..0x18].try_into().unwrap());
    let v6 = (((o10 & 0xFF) << 8) | ((o10 & 0xFF00) << 16)) & 0xFFFFFFFF;
    let check1 = o14 == 0x20204000;
    let check2 = (v6.wrapping_sub(0x200)) <= 0xFE00;
    let check3 = (v6.wrapping_sub(1) & v6) == 0;
    if !(check1 && check2 && check3) { return; }
    let tmp = buf[0x08..0x10].to_vec();
    buf[0x10..0x18].copy_from_slice(&tmp);
    let key = derive_page_key(1);
    let iv = derive_page_iv(1);
    let dec = aes_cbc_decrypt(&buf[0x10..PAGE_SIZE], &key, &iv);
    buf[0x10..PAGE_SIZE].copy_from_slice(&dec);
    buf[..16].copy_from_slice(SQLITE_HEADER);
}

fn tea_decrypt_block(block: &[u8], key: &[u8]) -> [u8; 8] {
    let mut v0 = u32::from_be_bytes(block[0..4].try_into().unwrap());
    let mut v1 = u32::from_be_bytes(block[4..8].try_into().unwrap());
    let k: [u32; 4] = [
        u32::from_be_bytes(key[0..4].try_into().unwrap()),
        u32::from_be_bytes(key[4..8].try_into().unwrap()),
        u32::from_be_bytes(key[8..12].try_into().unwrap()),
        u32::from_be_bytes(key[12..16].try_into().unwrap()),
    ];
    let mut s = TEA_DELTA.wrapping_mul(16);
    for _ in 0..16 {
        let t = (v0 << 4).wrapping_add(k[2]) ^ v0.wrapping_add(s) ^ (v0 >> 5).wrapping_add(k[3]);
        v1 = v1.wrapping_sub(t);
        let t = (v1 << 4).wrapping_add(k[0]) ^ v1.wrapping_add(s) ^ (v1 >> 5).wrapping_add(k[1]);
        v0 = v0.wrapping_sub(t);
        s = s.wrapping_sub(TEA_DELTA);
    }
    let mut out = [0u8; 8];
    out[0..4].copy_from_slice(&v0.to_be_bytes());
    out[4..8].copy_from_slice(&v1.to_be_bytes());
    out
}

fn decrypt_tencent_tea(input: &[u8], key: &[u8]) -> Result<Vec<u8>, String> {
    const SALT_LEN: usize = 2;
    const ZERO_LEN: usize = 7;
    if input.len() % 8 != 0 || input.len() < 16 { return Err("invalid TEA input".into()); }
    let mut dest = tea_decrypt_block(&input[..8], key).to_vec();
    let pad_len = (dest[0] & 0x7) as usize;
    let out_len = input.len().checked_sub(1 + pad_len + SALT_LEN + ZERO_LEN)
        .ok_or("invalid TEA padding")?;
    let mut out = vec![0u8; out_len];
    let mut iv_prev = vec![0u8; 8];
    let mut iv_cur = input[..8].to_vec();
    let mut in_pos = 8usize;
    let mut dest_idx = 1 + pad_len;
    let mut crypt_block = |dest: &mut Vec<u8>, iv_prev: &mut Vec<u8>, iv_cur: &mut Vec<u8>,
                           in_pos: &mut usize, dest_idx: &mut usize| {
        std::mem::swap(iv_prev, iv_cur);
        *iv_cur = input[*in_pos..*in_pos + 8].to_vec();
        for i in 0..8 { dest[i] ^= iv_cur[i]; }
        *dest = tea_decrypt_block(dest, key).to_vec();
        *in_pos += 8;
        *dest_idx = 0;
    };
    let mut i = 1usize;
    while i <= SALT_LEN {
        if dest_idx < 8 { dest_idx += 1; i += 1; }
        else { crypt_block(&mut dest, &mut iv_prev, &mut iv_cur, &mut in_pos, &mut dest_idx); }
    }
    let mut out_pos = 0usize;
    while out_pos < out_len {
        if dest_idx < 8 {
            out[out_pos] = dest[dest_idx] ^ iv_prev[dest_idx];
            dest_idx += 1; out_pos += 1;
        } else { crypt_block(&mut dest, &mut iv_prev, &mut iv_cur, &mut in_pos, &mut dest_idx); }
    }
    Ok(out)
}

fn simple_make_key(salt: u8, length: usize) -> Vec<u8> {
    (0..length).map(|i| {
        let tmp = ((salt as f64) + (i as f64) * 0.1).tan().abs() * 100.0;
        tmp as u8
    }).collect()
}

fn derive_key_v1(raw: &[u8]) -> Result<Vec<u8>, String> {
    if raw.len() < 16 { return Err("key too short".into()); }
    let sk = simple_make_key(106, 8);
    let mut tea_key = vec![0u8; 16];
    for i in 0..8 {
        tea_key[i * 2] = sk[i];
        tea_key[i * 2 + 1] = raw[i];
    }
    let decrypted = decrypt_tencent_tea(&raw[8..], &tea_key)?;
    let mut result = raw[..8].to_vec();
    result.extend(decrypted);
    Ok(result)
}

fn derive_key_v2(raw: &[u8]) -> Result<Vec<u8>, String> {
    let k1: [u8; 16] = [0x33,0x38,0x36,0x5A,0x4A,0x59,0x21,0x40,0x23,0x2A,0x24,0x25,0x5E,0x26,0x29,0x28];
    let k2: [u8; 16] = [0x2A,0x2A,0x23,0x21,0x28,0x23,0x24,0x25,0x26,0x5E,0x61,0x31,0x63,0x5A,0x2C,0x54];
    let buf = decrypt_tencent_tea(raw, &k1)?;
    let buf = decrypt_tencent_tea(&buf, &k2)?;
    let decoded = base64::engine::general_purpose::STANDARD.decode(&buf)
        .map_err(|e| format!("base64 error: {}", e))?;
    Ok(decoded)
}

fn derive_key(ekey: &str) -> Result<Vec<u8>, String> {
    let raw = base64::engine::general_purpose::STANDARD.decode(ekey)
        .map_err(|e| format!("base64 error: {}", e))?;
    let v2_prefix = b"QQMusic EncV2,Key:";
    let raw = if raw.starts_with(v2_prefix) {
        derive_key_v2(&raw[v2_prefix.len()..])?
    } else { raw };
    derive_key_v1(&raw)
}

struct MapCipher { key: Vec<u8>, size: usize }
impl MapCipher {
    fn new(key: Vec<u8>) -> Self { let size = key.len(); Self { key, size } }
    fn mask(&self, offset: usize) -> u8 {
        let offset = if offset > 0x7FFF { offset % 0x7FFF } else { offset };
        let idx = (offset * offset + 71214) % self.size;
        let v = self.key[idx];
        let r = ((idx as u8 & 0x7) + 4) % 8;
        ((v << r) | (v >> r)) & 0xFF
    }
    fn decrypt(&self, buf: &mut [u8], offset: usize) {
        for i in 0..buf.len() { buf[i] ^= self.mask(offset + i); }
    }
}

struct Rc4Cipher { key: Vec<u8>, n: usize, box_state: Vec<u8>, hash: u32 }
impl Rc4Cipher {
    const SEG: usize = 5120;
    const FIRST: usize = 128;
    fn new(key: Vec<u8>) -> Self {
        let n = key.len();
        let mut bx: Vec<u8> = (0..n).map(|i| (i & 0xFF) as u8).collect();
        let mut j = 0usize;
        for i in 0..n { j = (j + bx[i] as usize + key[i % n] as usize) % n; bx.swap(i, j); }
        let mut c = Self { key, n, box_state: bx, hash: 1 };
        c.compute_hash_base();
        c
    }
    fn compute_hash_base(&mut self) {
        self.hash = 1;
        for i in 0..self.n {
            let v = self.key[i] as u32;
            if v == 0 { continue; }
            let next = self.hash.wrapping_mul(v);
            if next == 0 || next <= self.hash { break; }
            self.hash = next;
        }
    }
    fn seg_skip(&self, id: usize) -> usize {
        let seed = self.key[id % self.n] as usize;
        let denom = (id + 1) * seed;
        if denom == 0 { return 0; }
        let val = (self.hash as f64) / (denom as f64) * 100.0;
        if val.is_nan() || val.is_infinite() { return 0; }
        (val as usize) % self.n
    }
    fn decrypt(&self, buf: &mut [u8], offset: usize) {
        let mut off = offset; let mut processed = 0usize; let mut to_go = buf.len();
        if off < Self::FIRST { let sz = to_go.min(Self::FIRST - off); self.enc_first(&mut buf[processed..processed + sz], off); off += sz; to_go -= sz; processed += sz; }
        if to_go > 0 && off % Self::SEG != 0 { let sz = to_go.min(Self::SEG - off % Self::SEG); self.enc_seg(&mut buf[processed..processed + sz], off); off += sz; to_go -= sz; processed += sz; }
        while to_go > Self::SEG { self.enc_seg(&mut buf[processed..processed + Self::SEG], off); off += Self::SEG; to_go -= Self::SEG; processed += Self::SEG; }
        if to_go > 0 { self.enc_seg(&mut buf[processed..], off); }
    }
    fn enc_first(&self, buf: &mut [u8], offset: usize) { for i in 0..buf.len() { buf[i] ^= self.key[self.seg_skip(offset + i)]; } }
    fn enc_seg(&self, buf: &mut [u8], offset: usize) {
        let mut bx = self.box_state.clone(); let mut j = 0usize; let mut k = 0usize;
        let skip = (offset % Self::SEG) + self.seg_skip(offset / Self::SEG);
        for i in -(skip as isize)..(buf.len() as isize) {
            j = (j + 1) % self.n; k = (bx[j] as usize + k) % self.n; bx.swap(j, k);
            if i >= 0 { buf[i as usize] ^= bx[(bx[j] as usize + bx[k] as usize) % self.n]; }
        }
    }
}

enum QmcCipher { Map(MapCipher), Rc4(Rc4Cipher) }
impl QmcCipher {
    fn new(key: Vec<u8>) -> Option<Self> {
        if key.len() > 300 { Some(Self::Rc4(Rc4Cipher::new(key))) }
        else if !key.is_empty() { Some(Self::Map(MapCipher::new(key))) }
        else { None }
    }
    fn decrypt(&self, buf: &mut [u8], offset: usize) {
        match self { Self::Map(m) => m.decrypt(buf, offset), Self::Rc4(r) => r.decrypt(buf, offset) }
    }
}

struct KggHeader { audio_offset: usize, audio_hash: String }
fn parse_kgg_header(data: &[u8]) -> Result<KggHeader, String> {
    if data.len() < 0x4C || data[..16] != KGM_MAGIC { return Err("invalid KGG file".into()); }
    let audio_offset = u32::from_le_bytes(data[0x10..0x14].try_into().unwrap()) as usize;
    let crypto_ver = u32::from_le_bytes(data[0x14..0x18].try_into().unwrap());
    if crypto_ver != 5 { return Err(format!("unsupported crypto version {}", crypto_ver)); }
    let pos = 0x3C + 8;
    let hash_len = u32::from_le_bytes(data[pos..pos+4].try_into().unwrap()) as usize;
    let audio_hash = String::from_utf8_lossy(&data[pos+4..pos+4+hash_len]).to_string();
    Ok(KggHeader { audio_offset, audio_hash })
}

fn sniff_ext(data: &[u8]) -> &'static str {
    if data.starts_with(b"ID3") { "mp3" }
    else if data.starts_with(b"\xff\xfb") || data.starts_with(b"\xff\xf3") || data.starts_with(b"\xff\xfa") { "mp3" }
    else if data.starts_with(b"fLaC") { "flac" }
    else if data.starts_with(b"OggS") { "ogg" }
    else { "bin" }
}

fn extract_ekey_map(db_bytes: &[u8]) -> Result<HashMap<String, String>, String> {
    let tmp = tempfile::NamedTempFile::new().map_err(|e| e.to_string())?;
    std::fs::write(tmp.path(), db_bytes).map_err(|e| e.to_string())?;
    let conn = Connection::open(tmp.path()).map_err(|e| e.to_string())?;
    let mut result = HashMap::new();
    let mut stmt = conn.prepare("SELECT EncryptionKeyId, EncryptionKey FROM ShareFileItems WHERE EncryptionKey IS NOT NULL AND EncryptionKey != ''").map_err(|e| e.to_string())?;
    let rows = stmt.query_map([], |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))).map_err(|e| e.to_string())?;
    for row in rows { if let Ok((k, v)) = row { if !v.is_empty() { result.insert(k, v); } } }
    Ok(result)
}

fn query_song_list(db_bytes: &[u8]) -> Result<Vec<SongInfo>, String> {
    let tmp = tempfile::NamedTempFile::new().map_err(|e| e.to_string())?;
    std::fs::write(tmp.path(), db_bytes).map_err(|e| e.to_string())?;
    let conn = Connection::open(tmp.path()).map_err(|e| e.to_string())?;
    let mut stmt = conn.prepare("SELECT FileName, FileNamePure, SongName, Artist, Album, BitRate, Duration, FileSize, Quality, EncryptionKeyId FROM ShareFileItems WHERE EncryptionKey IS NOT NULL AND EncryptionKey != '' ORDER BY id").map_err(|e| e.to_string())?;
    let rows = stmt.query_map([], |row| {
        let fn_name: String = row.get::<_, Option<String>>(0)?.unwrap_or_default();
        let fn_pure: String = row.get::<_, Option<String>>(1)?.unwrap_or_default();
        let song: String = row.get::<_, Option<String>>(2)?.unwrap_or_default();
        let artist: String = row.get::<_, Option<String>>(3)?.unwrap_or_default();
        let album: String = row.get::<_, Option<String>>(4)?.unwrap_or_default();
        let bitrate: i64 = row.get::<_, Option<i64>>(5)?.unwrap_or(0);
        let duration: i64 = row.get::<_, Option<i64>>(6)?.unwrap_or(0);
        let fsize: i64 = row.get::<_, Option<i64>>(7)?.unwrap_or(0);
        let quality: String = row.get::<_, Option<String>>(8)?.unwrap_or_default();
        let ek_id: String = row.get::<_, Option<String>>(9)?.unwrap_or_default();
        let display = if !song.is_empty() { song.clone() } else if !fn_pure.is_empty() { fn_pure.clone() } else { fn_name.clone() };
        Ok(SongInfo { filename: fn_pure, display_name: display, song_name: song, artist, album, bitrate, duration_ms: duration, file_size: fsize, quality, audio_hash: ek_id })
    }).map_err(|e| e.to_string())?;
    let mut songs = Vec::new();
    for row in rows { if let Ok(s) = row { songs.push(s); } }
    Ok(songs)
}

fn find_db_path() -> Option<std::path::PathBuf> {
    let appdata = std::env::var("APPDATA").ok()?;
    let candidates = [std::path::Path::new(&appdata).join("KuGou8"), std::path::PathBuf::from(".")];
    for dir in &candidates {
        if let Ok(entries) = std::fs::read_dir(dir) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().map_or(false, |e| e == "db") {
                    if path.file_name().map_or(false, |n| n.to_string_lossy().contains("KGMusicV3")) { return Some(path); }
                }
            }
        }
    }
    None
}

// ---- Monitor ----
struct MonitorState { watcher: Option<notify::RecommendedWatcher> }

#[derive(Serialize, Clone)]
struct MonitorEvent { event_type: String, filename: String, message: String }

fn wait_for_stable(path: &Path) -> bool {
    let mut last_size = 0u64; let mut stable = 0;
    for _ in 0..60 {
        match std::fs::metadata(path) {
            Ok(m) => { let sz = m.len(); if sz == last_size && sz > 0 { stable += 1; if stable >= 4 { return true; } } else { stable = 0; } last_size = sz; }
            Err(_) => return false,
        }
        std::thread::sleep(std::time::Duration::from_millis(500));
    }
    false
}

fn decrypt_kgg_bytes(file_data: &[u8]) -> Result<(Vec<u8>, String), String> {
    let header = parse_kgg_header(file_data)?;
    let db_path = find_db_path().ok_or("KuGou database not found")?;
    let db_raw = std::fs::read(&db_path).map_err(|e| e.to_string())?;
    let db_plain = decrypt_database(&db_raw);
    let ekey_map = extract_ekey_map(&db_plain)?;
    let ekey = ekey_map.get(&header.audio_hash).ok_or(format!("ekey not found for hash {}", header.audio_hash))?;
    let raw_key = derive_key(ekey)?;
    let cipher = QmcCipher::new(raw_key).ok_or("cipher creation failed")?;
    let mut audio = file_data[header.audio_offset..].to_vec();
    cipher.decrypt(&mut audio, 0);
    let fmt = sniff_ext(&audio).to_string();
    if fmt == "bin" { return Err("unrecognized audio format".into()); }
    Ok((audio, fmt))
}

fn find_kugou_download_dir() -> Option<String> {
    let candidates = ["D:\\KuGou\\KugouMusic", "D:\\KuGou", "D:\\Music\\KuGou", "C:\\KuGou\\KugouMusic"];
    for c in &candidates { if Path::new(c).exists() { return Some(c.to_string()); } }
    let home = std::env::var("USERPROFILE").ok()?;
    let music = Path::new(&home).join("Music").join("KuGou");
    if music.exists() { return Some(music.to_string_lossy().into()); }
    None
}

// ---- Tauri types ----
#[derive(Serialize)]
struct SongInfo { filename: String, display_name: String, song_name: String, artist: String, album: String, bitrate: i64, duration_ms: i64, file_size: i64, quality: String, audio_hash: String }

#[derive(Serialize)]
struct DecryptResultData { audio: Vec<u8>, format: String, title: String }

#[derive(Serialize)]
struct SongListResult { success: bool, total: usize, songs: Vec<SongInfo>, error: Option<String> }

#[derive(Serialize, Clone)]
struct BatchItem { filename: String, success: bool, format: String, error: Option<String> }

#[derive(Serialize)]
struct BatchResult { total: usize, succeeded: usize, failed: usize, items: Vec<BatchItem> }

// ---- Commands ----
#[tauri::command]
fn decrypt_kgg(file_data: Vec<u8>, filename: String) -> Result<DecryptResultData, String> {
    let (audio, fmt) = decrypt_kgg_bytes(&file_data)?;
    let title = std::path::Path::new(&filename).file_stem().map(|s| s.to_string_lossy().to_string()).unwrap_or(filename);
    Ok(DecryptResultData { audio, format: fmt, title })
}

#[tauri::command]
fn get_songs() -> SongListResult {
    match find_db_path() {
        Some(path) => match std::fs::read(&path) {
            Ok(raw) => { let plain = decrypt_database(&raw); match query_song_list(&plain) { Ok(songs) => SongListResult { success: true, total: songs.len(), songs, error: None }, Err(e) => SongListResult { success: false, total: 0, songs: vec![], error: Some(e) } } }
            Err(e) => SongListResult { success: false, total: 0, songs: vec![], error: Some(e.to_string()) }
        },
        None => SongListResult { success: false, total: 0, songs: vec![], error: Some("Database not found".into()) }
    }
}

#[tauri::command]
fn start_monitor(watch_dir: String, output_dir: String, state: tauri::State<'_, std::sync::Mutex<MonitorState>>, app: tauri::AppHandle) -> Result<String, String> {
    { let mut s = state.lock().unwrap(); s.watcher = None; }
    let out_dir = output_dir.clone();
    let app_h = app.clone();
    let mut watcher = notify::recommended_watcher(move |res: Result<Event, _>| {
        if let Ok(event) = res {
            if !matches!(event.kind, EventKind::Create(_) | EventKind::Modify(_)) { return; }
            for p in &event.paths {
                if p.extension().map_or(false, |e| e == "kgg") {
                    let fp = p.clone(); let od = out_dir.clone(); let ah = app_h.clone();
                    let fname = fp.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
                    let _ = ah.emit("monitor-event", MonitorEvent { event_type: "detect".into(), filename: fname.clone(), message: "detected".into() });
                    std::thread::spawn(move || {
                        if !wait_for_stable(&fp) { let _ = ah.emit("monitor-event", MonitorEvent { event_type: "error".into(), filename: fname, message: "timeout".into() }); return; }
                        match std::fs::read(&fp) {
                            Ok(data) => match decrypt_kgg_bytes(&data) {
                                Ok((audio, fmt)) => {
                                    let stem = fp.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or("output".into());
                                    let out_path = Path::new(&od).join(stem + "." + &fmt);
                                    match std::fs::write(&out_path, &audio) {
                                        Ok(_) => { let _ = ah.emit("monitor-event", MonitorEvent { event_type: "success".into(), filename: fname, message: format!(".{}", fmt) }); }
                                        Err(e) => { let _ = ah.emit("monitor-event", MonitorEvent { event_type: "error".into(), filename: fname, message: format!("save: {}", e) }); }
                                    }
                                }
                                Err(e) => { let _ = ah.emit("monitor-event", MonitorEvent { event_type: "error".into(), filename: fname, message: e }); }
                            },
                            Err(e) => { let _ = ah.emit("monitor-event", MonitorEvent { event_type: "error".into(), filename: fname, message: format!("read: {}", e) }); }
                        }
                    });
                }
            }
        }
    }).map_err(|e| e.to_string())?;
    watcher.watch(Path::new(&watch_dir), RecursiveMode::NonRecursive).map_err(|e| e.to_string())?;
    { let mut s = state.lock().unwrap(); s.watcher = Some(watcher); }
    Ok("ok".into())
}

#[tauri::command]
fn stop_monitor(state: tauri::State<'_, std::sync::Mutex<MonitorState>>) -> Result<String, String> {
    let mut s = state.lock().unwrap(); s.watcher = None; Ok("ok".into())
}

#[tauri::command]
fn batch_decrypt(input_dir: String, output_dir: String, app: tauri::AppHandle) -> Result<BatchResult, String> {
    let mut items = Vec::new();
    let mut succeeded = 0usize;
    let mut failed = 0usize;
    let entries = std::fs::read_dir(&input_dir).map_err(|e| e.to_string())?;
    let mut kgg_files: Vec<_> = entries.flatten()
        .filter(|e| e.path().extension().map_or(false, |ext| ext == "kgg"))
        .collect();
    kgg_files.sort_by_key(|e| e.path());
    let total = kgg_files.len();
    for entry in kgg_files {
        let path = entry.path();
        let fname = path.file_stem().map(|s| s.to_string_lossy().into_owned()).unwrap_or_default();
        let _ = app.emit("monitor-event", MonitorEvent {
            event_type: "detect".into(), filename: fname.clone(), message: "batch".into()
        });
        match std::fs::read(&path) {
            Ok(data) => match decrypt_kgg_bytes(&data) {
                Ok((audio, fmt)) => {
                    let out_name = format!("{}.{}", fname, fmt);
                    let out_path = Path::new(&output_dir).join(&out_name);
                    match std::fs::write(&out_path, &audio) {
                        Ok(_) => {
                            succeeded += 1;
                            let _ = app.emit("monitor-event", MonitorEvent {
                                event_type: "success".into(), filename: fname.clone(), message: format!(".{}", fmt)
                            });
                            items.push(BatchItem { filename: fname, success: true, format: fmt, error: None });
                        }
                        Err(e) => {
                            failed += 1;
                            let msg = format!("save: {}", e);
                            let _ = app.emit("monitor-event", MonitorEvent {
                                event_type: "error".into(), filename: fname.clone(), message: msg.clone()
                            });
                            items.push(BatchItem { filename: fname, success: false, format: String::new(), error: Some(msg) });
                        }
                    }
                }
                Err(e) => {
                    failed += 1;
                    let _ = app.emit("monitor-event", MonitorEvent {
                        event_type: "error".into(), filename: fname.clone(), message: e.clone()
                    });
                    items.push(BatchItem { filename: fname, success: false, format: String::new(), error: Some(e) });
                }
            },
            Err(e) => {
                failed += 1;
                let msg = format!("read: {}", e);
                let _ = app.emit("monitor-event", MonitorEvent {
                    event_type: "error".into(), filename: fname.clone(), message: msg.clone()
                });
                items.push(BatchItem { filename: fname, success: false, format: String::new(), error: Some(msg) });
            }
        }
    }
    Ok(BatchResult { total, succeeded, failed, items })
}

#[tauri::command]
fn get_kugou_dir() -> Option<String> { find_kugou_download_dir() }

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init()).plugin(tauri_plugin_dialog::init())
        .manage(std::sync::Mutex::new(MonitorState { watcher: None }))
        .invoke_handler(tauri::generate_handler![decrypt_kgg, get_songs, start_monitor, stop_monitor, get_kugou_dir, batch_decrypt])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
