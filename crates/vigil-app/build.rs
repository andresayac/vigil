//! Embeds Vigil's icon (resource 1: Explorer, the taskbar and the window use it) and the version
//! resource (Properties > Details, Installed apps). GPUI embeds the application manifest.

use std::path::PathBuf;

fn main() {
    println!("cargo:rerun-if-changed=icons/icon.ico");
    println!("cargo:rerun-if-changed=build.rs");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap_or_default());
    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap_or_default());
    let version = std::env::var("CARGO_PKG_VERSION").unwrap_or_default();
    let numbers: Vec<u16> = version
        .split(['.', '-', '+'])
        .take(3)
        .map(|part| part.parse().unwrap_or(0))
        .collect();
    let number = |i: usize| numbers.get(i).copied().unwrap_or(0);
    let icon = manifest_dir
        .join("icons")
        .join("icon.ico")
        .display()
        .to_string()
        .replace('\\', "/");
    let script = format!(
        r#"#include <winver.h>
1 ICON "{icon}"
VS_VERSION_INFO VERSIONINFO
FILEVERSION {a},{b},{c},0
PRODUCTVERSION {a},{b},{c},0
FILEFLAGSMASK 0x3fL
FILEFLAGS 0x0L
FILEOS VOS_NT_WINDOWS32
FILETYPE VFT_APP
FILESUBTYPE 0x0L
BEGIN
  BLOCK "StringFileInfo"
  BEGIN
    BLOCK "040904b0"
    BEGIN
      VALUE "CompanyName", "andresayac"
      VALUE "FileDescription", "Vigil"
      VALUE "FileVersion", "{version}"
      VALUE "InternalName", "vigil"
      VALUE "LegalCopyright", "andresayac (MIT License)"
      VALUE "OriginalFilename", "vigil.exe"
      VALUE "ProductName", "Vigil"
      VALUE "ProductVersion", "{version}"
    END
  END
  BLOCK "VarFileInfo"
  BEGIN
    VALUE "Translation", 0x409, 1200
  END
END
"#,
        a = number(0),
        b = number(1),
        c = number(2),
    );
    let path = out_dir.join("vigil.rc");
    if let Err(error) = std::fs::write(&path, script) {
        println!("cargo:warning=the version resource was not written: {error}");
        return;
    }
    if let Err(error) = embed_resource::compile(&path, embed_resource::NONE).manifest_optional() {
        println!("cargo:warning=the icon and version were not embedded: {error}");
    }
}
