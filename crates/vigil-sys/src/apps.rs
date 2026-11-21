//! What Task Manager shows about a program beyond the raw process list: whether it owns a window
//! on the desktop (an "app"), its friendly name (the file description of its executable) and its
//! icon. Read-only.
//!
//! Descriptions and icons are cached per executable path for the life of the process: they are read
//! once, when a program is first seen, never on every sample.

use std::collections::{HashMap, HashSet};
use std::ffi::c_void;
use std::sync::{LazyLock, Mutex, PoisonError};

use windows::Win32::Foundation::{HWND, LPARAM};
use windows::Win32::Graphics::Dwm::{DWMWA_CLOAKED, DwmGetWindowAttribute};
use windows::Win32::Graphics::Gdi::{
    BI_RGB, BITMAP, BITMAPINFO, BITMAPINFOHEADER, CreateCompatibleDC, DIB_RGB_COLORS, DeleteDC, DeleteObject,
    GetDIBits, GetObjectW, HBITMAP, HGDIOBJ,
};
use windows::Win32::Storage::FileSystem::{GetFileVersionInfoSizeW, GetFileVersionInfoW, VerQueryValueW};
use windows::Win32::UI::Shell::ExtractIconExW;
use windows::Win32::UI::WindowsAndMessaging::{
    DestroyIcon, EnumWindows, GW_OWNER, GWL_EXSTYLE, GetIconInfo, GetWindow, GetWindowLongW, GetWindowTextLengthW,
    GetWindowThreadProcessId, HICON, ICONINFO, IsWindowVisible, WS_EX_TOOLWINDOW,
};
use windows::core::{BOOL, PCWSTR};

use crate::util::{from_wide, wide};

static DESCRIPTIONS: LazyLock<Mutex<HashMap<String, String>>> = LazyLock::new(|| Mutex::new(HashMap::new()));
static ICONS: LazyLock<Mutex<HashMap<String, Option<String>>>> = LazyLock::new(|| Mutex::new(HashMap::new()));

// --------------------------------------------------------------------------- windows

unsafe extern "system" fn collect_window(hwnd: HWND, data: LPARAM) -> BOOL {
    // SAFETY: `data` is the address of the HashSet passed by `window_pids`, alive during EnumWindows.
    let pids = unsafe { &mut *(data.0 as *mut HashSet<u32>) };
    if is_app_window(hwnd) {
        let mut pid = 0u32;
        // SAFETY: `pid` is a valid out pointer.
        unsafe { GetWindowThreadProcessId(hwnd, Some(&mut pid)) };
        if pid != 0 {
            pids.insert(pid);
        }
    }
    BOOL(1)
}

/// A window Task Manager would count as an app's: visible, not owned by another window, not a tool
/// window, not cloaked (hidden UWP frames and windows on other virtual desktops count as visible),
/// and with a title.
fn is_app_window(hwnd: HWND) -> bool {
    // SAFETY: plain queries on a window handle EnumWindows handed us.
    unsafe {
        if !IsWindowVisible(hwnd).as_bool() {
            return false;
        }
        if GetWindow(hwnd, GW_OWNER).is_ok_and(|owner| !owner.is_invalid()) {
            return false;
        }
        if (GetWindowLongW(hwnd, GWL_EXSTYLE) as u32) & WS_EX_TOOLWINDOW.0 != 0 {
            return false;
        }
        if GetWindowTextLengthW(hwnd) == 0 {
            return false;
        }
        let mut cloaked = 0u32;
        let ok = DwmGetWindowAttribute(
            hwnd,
            DWMWA_CLOAKED,
            (&raw mut cloaked).cast::<c_void>(),
            size_of::<u32>() as u32,
        );
        !(ok.is_ok() && cloaked != 0)
    }
}

/// The processes that own an app window on the desktop. One EnumWindows pass (a few hundred windows,
/// well under a millisecond).
pub fn window_pids() -> HashSet<u32> {
    let mut pids: HashSet<u32> = HashSet::new();
    // SAFETY: the callback only uses `pids` through the pointer for the duration of the call.
    let _ = unsafe { EnumWindows(Some(collect_window), LPARAM((&raw mut pids) as isize)) };
    pids
}

// --------------------------------------------------------------------------- file description

fn query_string(block: &[u8], query: &str) -> Option<String> {
    let mut pointer: *mut c_void = std::ptr::null_mut();
    let mut length = 0u32;
    let query = wide(query);
    // SAFETY: `block` holds a version resource read by GetFileVersionInfoW; the out pointers are valid.
    let found = unsafe { VerQueryValueW(block.as_ptr().cast(), PCWSTR(query.as_ptr()), &mut pointer, &mut length) };
    if !found.as_bool() || pointer.is_null() || length == 0 {
        return None;
    }
    // SAFETY: VerQueryValueW points inside `block` at `length` UTF-16 units (terminator included).
    let units = unsafe { std::slice::from_raw_parts(pointer.cast::<u16>(), length as usize) };
    let text = from_wide(units).trim().to_string();
    (!text.is_empty()).then_some(text)
}

fn read_description(path: &str) -> Option<String> {
    let name = wide(path);
    // SAFETY: `name` is NUL-terminated.
    let size = unsafe { GetFileVersionInfoSizeW(PCWSTR(name.as_ptr()), None) };
    if size == 0 || size > 4 * 1024 * 1024 {
        return None;
    }
    let mut block = vec![0u8; size as usize];
    // SAFETY: `block` is writable for `size` bytes.
    unsafe { GetFileVersionInfoW(PCWSTR(name.as_ptr()), None, size, block.as_mut_ptr().cast()) }.ok()?;
    // The first translation the file declares, then the usual US English / Unicode fallback.
    let mut pointer: *mut c_void = std::ptr::null_mut();
    let mut length = 0u32;
    let translation = wide(r"\VarFileInfo\Translation");
    let mut codes: Vec<String> = Vec::new();
    // SAFETY: as in `query_string`.
    let found = unsafe {
        VerQueryValueW(
            block.as_ptr().cast(),
            PCWSTR(translation.as_ptr()),
            &mut pointer,
            &mut length,
        )
    };
    if found.as_bool() && !pointer.is_null() && length >= 4 {
        // SAFETY: the translation table is an array of (language, code page) u16 pairs.
        let pairs = unsafe { std::slice::from_raw_parts(pointer.cast::<u16>(), (length / 2) as usize) };
        for pair in pairs.as_chunks::<2>().0.iter().take(4) {
            codes.push(format!("{:04x}{:04x}", pair[0], pair[1]));
        }
    }
    codes.extend(["040904b0".to_string(), "040904e4".to_string(), "000004b0".to_string()]);
    codes
        .iter()
        .find_map(|code| query_string(&block, &format!(r"\StringFileInfo\{code}\FileDescription")))
}

/// The file description of an executable ("Google Chrome", "Visual Studio Code"), cached per path.
/// None when the file has no version resource or cannot be read.
pub fn file_description(path: &str) -> Option<String> {
    if path.is_empty() {
        return None;
    }
    let key = path.to_lowercase();
    if let Some(known) = DESCRIPTIONS.lock().unwrap_or_else(PoisonError::into_inner).get(&key) {
        return (!known.is_empty()).then(|| known.clone());
    }
    let found = read_description(path).unwrap_or_default();
    DESCRIPTIONS
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(key, found.clone());
    (!found.is_empty()).then_some(found)
}

// --------------------------------------------------------------------------- icons

struct Gdi(HGDIOBJ);

impl Drop for Gdi {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // SAFETY: the object came from GetIconInfo and is deleted once.
            unsafe {
                let _ = DeleteObject(self.0);
            }
        }
    }
}

/// Top-down BGRA pixels of a bitmap.
fn bitmap_pixels(bitmap: HBITMAP) -> Option<(u32, u32, Vec<u8>)> {
    let mut info = BITMAP::default();
    // SAFETY: `info` is a BITMAP of the size passed.
    let read = unsafe { GetObjectW(bitmap.into(), size_of::<BITMAP>() as i32, Some((&raw mut info).cast())) };
    if read == 0 || info.bmWidth <= 0 || info.bmHeight <= 0 || info.bmWidth > 256 || info.bmHeight > 256 {
        return None;
    }
    let (width, height) = (info.bmWidth as u32, info.bmHeight as u32);
    let mut header = BITMAPINFO {
        bmiHeader: BITMAPINFOHEADER {
            biSize: size_of::<BITMAPINFOHEADER>() as u32,
            biWidth: width as i32,
            biHeight: -(height as i32),
            biPlanes: 1,
            biBitCount: 32,
            biCompression: BI_RGB.0,
            ..Default::default()
        },
        ..Default::default()
    };
    let mut pixels = vec![0u8; (width * height * 4) as usize];
    // SAFETY: a memory DC compatible with the screen; deleted below.
    let dc = unsafe { CreateCompatibleDC(None) };
    if dc.is_invalid() {
        return None;
    }
    // SAFETY: `pixels` has room for width*height 32-bit pixels, as the header describes.
    let lines = unsafe {
        GetDIBits(
            dc,
            bitmap,
            0,
            height,
            Some(pixels.as_mut_ptr().cast()),
            &mut header,
            DIB_RGB_COLORS,
        )
    };
    // SAFETY: the DC was created above.
    unsafe {
        let _ = DeleteDC(dc);
    }
    (lines == height as i32).then_some((width, height, pixels))
}

/// RGBA pixels of an icon (alpha from the colour bitmap, or from the mask for old icons).
fn icon_rgba(icon: HICON) -> Option<(u32, u32, Vec<u8>)> {
    let mut info = ICONINFO::default();
    // SAFETY: `info` receives two bitmaps that are deleted by the Gdi guards.
    unsafe { GetIconInfo(icon, &mut info) }.ok()?;
    let color = Gdi(info.hbmColor.into());
    let mask = Gdi(info.hbmMask.into());
    if info.hbmColor.is_invalid() {
        return None; // monochrome icon
    }
    let (width, height, mut pixels) = bitmap_pixels(info.hbmColor)?;
    let has_alpha = pixels.as_chunks::<4>().0.iter().any(|p| p[3] != 0);
    if !has_alpha {
        let (mw, mh, mask_pixels) = bitmap_pixels(info.hbmMask)?;
        if mw != width || mh < height {
            return None;
        }
        for (pixel, m) in pixels
            .as_chunks_mut::<4>()
            .0
            .iter_mut()
            .zip(mask_pixels.as_chunks::<4>().0)
        {
            // A white mask pixel is transparent.
            pixel[3] = if m[0] == 0 { 255 } else { 0 };
        }
    }
    drop((color, mask));
    for pixel in pixels.as_chunks_mut::<4>().0 {
        pixel.swap(0, 2); // BGRA -> RGBA
    }
    Some((width, height, pixels))
}

fn crc32(data: &[u8], mut crc: u32) -> u32 {
    crc = !crc;
    for byte in data {
        crc ^= u32::from(*byte);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ 0xEDB8_8320
            } else {
                crc >> 1
            };
        }
    }
    !crc
}

fn chunk(out: &mut Vec<u8>, kind: &[u8; 4], data: &[u8]) {
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    let start = out.len();
    out.extend_from_slice(kind);
    out.extend_from_slice(data);
    let crc = crc32(&out[start..], 0);
    out.extend_from_slice(&crc.to_be_bytes());
}

/// A PNG of RGBA pixels (stored deflate blocks: icons are a few KB, compression is not worth code).
pub fn encode_png(width: u32, height: u32, rgba: &[u8]) -> Vec<u8> {
    let mut raw = Vec::with_capacity(rgba.len() + height as usize);
    for row in rgba.chunks_exact((width * 4) as usize) {
        raw.push(0); // filter: none
        raw.extend_from_slice(row);
    }
    let mut zlib = vec![0x78, 0x01];
    let blocks: Vec<&[u8]> = raw.chunks(65_535).collect();
    for (index, block) in blocks.iter().enumerate() {
        zlib.push(u8::from(index + 1 == blocks.len()));
        let len = block.len() as u16;
        zlib.extend_from_slice(&len.to_le_bytes());
        zlib.extend_from_slice(&(!len).to_le_bytes());
        zlib.extend_from_slice(block);
    }
    let (mut a, mut b) = (1u32, 0u32);
    for byte in &raw {
        a = (a + u32::from(*byte)) % 65_521;
        b = (b + a) % 65_521;
    }
    zlib.extend_from_slice(&((b << 16) | a).to_be_bytes());

    let mut png = vec![0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A];
    let mut header = Vec::with_capacity(13);
    header.extend_from_slice(&width.to_be_bytes());
    header.extend_from_slice(&height.to_be_bytes());
    header.extend_from_slice(&[8, 6, 0, 0, 0]); // 8-bit RGBA
    chunk(&mut png, b"IHDR", &header);
    chunk(&mut png, b"IDAT", &zlib);
    chunk(&mut png, b"IEND", &[]);
    png
}

fn base64(data: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(data.len().div_ceil(3) * 4);
    for group in data.chunks(3) {
        let n = (u32::from(group[0]) << 16)
            | (u32::from(*group.get(1).unwrap_or(&0)) << 8)
            | u32::from(*group.get(2).unwrap_or(&0));
        out.push(TABLE[(n >> 18) as usize & 63] as char);
        out.push(TABLE[(n >> 12) as usize & 63] as char);
        out.push(if group.len() > 1 {
            TABLE[(n >> 6) as usize & 63] as char
        } else {
            '='
        });
        out.push(if group.len() > 2 {
            TABLE[n as usize & 63] as char
        } else {
            '='
        });
    }
    out
}

fn read_icon(path: &str) -> Option<String> {
    let name = wide(path);
    let mut large = HICON::default();
    // SAFETY: `name` is NUL-terminated; one icon is asked for and destroyed below.
    let count = unsafe { ExtractIconExW(PCWSTR(name.as_ptr()), 0, Some(&mut large), None, 1) };
    if count == 0 || large.is_invalid() {
        return None;
    }
    let pixels = icon_rgba(large);
    // SAFETY: the icon came from ExtractIconExW and is destroyed once.
    unsafe {
        let _ = DestroyIcon(large);
    }
    let (width, height, rgba) = pixels?;
    Some(format!(
        "data:image/png;base64,{}",
        base64(&encode_png(width, height, &rgba))
    ))
}

/// The icon of an executable as a PNG data URL (the shell's large icon, usually 32 px), cached per
/// path. None when the file has no icon.
pub fn icon_data_url(path: &str) -> Option<String> {
    if path.is_empty() {
        return None;
    }
    let key = path.to_lowercase();
    if let Some(known) = ICONS.lock().unwrap_or_else(PoisonError::into_inner).get(&key) {
        return known.clone();
    }
    let found = read_icon(path);
    ICONS
        .lock()
        .unwrap_or_else(PoisonError::into_inner)
        .insert(key, found.clone());
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn png_is_well_formed() {
        let png = encode_png(2, 1, &[255, 0, 0, 255, 0, 0, 255, 128]);
        assert_eq!(&png[..8], &[0x89, b'P', b'N', b'G', 0x0D, 0x0A, 0x1A, 0x0A]);
        assert_eq!(&png[12..16], b"IHDR");
        assert!(
            png.ends_with(&[0x49, 0x45, 0x4E, 0x44, 0xAE, 0x42, 0x60, 0x82]),
            "IEND with its CRC"
        );
        assert_eq!(crc32(b"IEND", 0), 0xAE42_6082);
    }

    #[test]
    fn base64_matches_the_standard() {
        assert_eq!(base64(b"Man"), "TWFu");
        assert_eq!(base64(b"Ma"), "TWE=");
        assert_eq!(base64(b"M"), "TQ==");
    }

    #[test]
    fn windows_tools_have_a_description_and_an_icon() {
        let root = std::env::var("SystemRoot").unwrap_or_else(|_| r"C:\Windows".into());
        let notepad = format!(r"{root}\System32\notepad.exe");
        let description = file_description(&notepad).unwrap_or_default();
        assert!(!description.is_empty(), "notepad has a file description");
        let icon = icon_data_url(&notepad).unwrap_or_default();
        assert!(
            icon.starts_with("data:image/png;base64,iVBORw0KGgo"),
            "{}",
            &icon[..icon.len().min(40)]
        );
        assert!(file_description(r"C:\nowhere\missing.exe").is_none());
        assert!(icon_data_url(r"C:\nowhere\missing.exe").is_none());
    }

    #[test]
    fn window_enumeration_runs() {
        // A test runner may have no desktop windows; the call must still succeed and be cheap.
        let started = std::time::Instant::now();
        let _ = window_pids();
        assert!(started.elapsed().as_millis() < 500);
    }
}
