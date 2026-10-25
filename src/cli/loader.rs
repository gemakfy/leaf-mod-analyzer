use std::fs::File;
use std::path::Path;

pub fn detect_loader(jar_path: &Path) -> String {
    let Ok(file) = File::open(jar_path) else {
        return "any".to_string();
    };
    let Ok(mut archive) = zip::ZipArchive::new(file) else {
        return "any".to_string();
    };

    let mut has_fabric = false;
    let mut has_forge = false;
    let mut has_neoforge = false;
    let mut has_quilt = false;

    for i in 0..archive.len() {
        if let Ok(entry) = archive.by_index(i) {
            if let Ok(name) = entry.name() {
                match name.as_ref() {
                    "fabric.mod.json" => has_fabric = true,
                    "quilt.mod.json" => has_quilt = true,
                    "META-INF/neoforge.mods.toml" => has_neoforge = true,
                    "META-INF/mods.toml" => has_forge = true,
                    _ => {}
                }
            }
        }
    }

    if has_quilt {
        "quilt".to_string()
    } else if has_fabric {
        "fabric".to_string()
    } else if has_neoforge {
        "neoforge".to_string()
    } else if has_forge {
        "forge".to_string()
    } else {
        "any".to_string()
    }
}
