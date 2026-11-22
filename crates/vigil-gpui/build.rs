//! Embeds Vigil's icon in the executable (resource 1: Explorer, the taskbar and GPUI's windows
//! use it).

fn main() {
    println!("cargo:rerun-if-changed=resources/vigil-gpui.rc");
    println!("cargo:rerun-if-changed=../vigil-app/icons/icon.ico");
    if std::env::var("CARGO_CFG_TARGET_OS").as_deref() != Ok("windows") {
        return;
    }
    if let Err(error) = embed_resource::compile("resources/vigil-gpui.rc", embed_resource::NONE).manifest_optional() {
        println!("cargo:warning=the icon was not embedded: {error}");
    }
}
