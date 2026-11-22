use std::path::Path;

fn main() {
    // Ensure ../frontend/dist exists at compile time so #[derive(RustEmbed)]
    // can always compile even before frontend assets are bundled (e.g. cargo test).
    let dist_dir = Path::new("../frontend/dist");
    if !dist_dir.exists() {
        let _ = std::fs::create_dir_all(dist_dir);
    }
    println!("cargo:rerun-if-changed=../frontend/dist");
}
