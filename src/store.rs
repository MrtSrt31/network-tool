//! Persistence: one JSON file per engagement under a data directory.
//! Override location with the NETWORKTOOL_DATA environment variable.

use crate::model::Engagement;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

pub fn data_dir() -> PathBuf {
    if let Ok(d) = std::env::var("NETWORKTOOL_DATA") {
        return PathBuf::from(d);
    }
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".to_string());
    Path::new(&home).join(".networktool").join("engagements")
}

pub fn ensure_dir() -> io::Result<PathBuf> {
    let d = data_dir();
    fs::create_dir_all(&d)?;
    Ok(d)
}

fn path_for(id: &str) -> PathBuf {
    data_dir().join(format!("{id}.json"))
}

fn to_io(e: serde_json::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, e)
}

pub fn save(e: &Engagement) -> io::Result<()> {
    ensure_dir()?;
    let json = serde_json::to_string_pretty(e).map_err(to_io)?;
    fs::write(path_for(&e.id), json)
}

pub fn load(id: &str) -> io::Result<Engagement> {
    let data = fs::read_to_string(path_for(id))?;
    serde_json::from_str(&data).map_err(to_io)
}

pub fn list() -> io::Result<Vec<Engagement>> {
    ensure_dir()?;
    let mut out = Vec::new();
    for entry in fs::read_dir(data_dir())? {
        let entry = entry?;
        let p = entry.path();
        if p.extension().and_then(|s| s.to_str()) == Some("json") {
            if let Ok(s) = fs::read_to_string(&p) {
                if let Ok(e) = serde_json::from_str::<Engagement>(&s) {
                    out.push(e);
                }
            }
        }
    }
    out.sort_by_key(|e| std::cmp::Reverse(e.created_at));
    Ok(out)
}
