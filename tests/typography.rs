//! The shared typography rule: no em-dash and no en-dash in anything this
//! repo authors. The page copy in every language, the public topic body
//! `report.rs` builds, the HTML shell in `pages.rs`, the README and the SQL
//! migrations all ship to a reader, so the scan walks the whole tree rather
//! than the one file the locale strings live in. Both the character and its
//! Rust escape are caught, and the test's own source carries neither: the
//! forms are built from their code points at runtime.

use std::path::Path;

/// The two banned code points, with the names the failure message uses.
const DASHES: [(&str, u32); 2] = [("em-dash", 0x2014), ("en-dash", 0x2013)];

/// Every `(line number, dash name)` hit in `text`, for the character itself
/// or its `\u{..}` escape.
fn dash_hits(text: &str) -> Vec<(usize, &'static str)> {
    let mut hits = Vec::new();
    for (name, code) in DASHES {
        let ch = char::from_u32(code).expect("a valid scalar");
        let escape = format!("\\u{{{code:x}}}");
        for (index, line) in text.lines().enumerate() {
            if line.contains(ch) || line.contains(&escape) {
                hits.push((index + 1, name));
            }
        }
    }
    hits
}

/// Every file under `dir` that is not build output or git metadata; binary
/// content (a non-UTF-8 read) is skipped, everything else is authored text.
fn authored_files(dir: &Path, acc: &mut Vec<std::path::PathBuf>) {
    for entry in std::fs::read_dir(dir).expect("read_dir") {
        let path = entry.expect("dir entry").path();
        let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
        if name == "target" || name == ".git" || name == "Cargo.lock" {
            continue;
        }
        if path.is_dir() {
            authored_files(&path, acc);
        } else {
            acc.push(path);
        }
    }
}

#[test]
fn no_authored_file_carries_a_dash() {
    let mut files = Vec::new();
    authored_files(Path::new("."), &mut files);
    assert!(
        files.iter().any(|p| p.ends_with("src/i18n.rs")),
        "the walk must reach the locale strings"
    );
    let mut offences = Vec::new();
    for path in files {
        let Ok(text) = std::fs::read_to_string(&path) else {
            continue;
        };
        for (line, name) in dash_hits(&text) {
            offences.push(format!("{}:{line} {name}", path.display()));
        }
    }
    assert!(
        offences.is_empty(),
        "dashes in authored text (use a comma, a colon, a period or parentheses): {offences:?}"
    );
}

/// The scan is only worth its runtime if it flags every form, so pin that on
/// synthetic lines carrying each one.
#[test]
fn the_scan_flags_the_character_and_the_escape_of_both_dashes() {
    for (name, code) in DASHES {
        let ch = char::from_u32(code).expect("a valid scalar");
        let as_char = format!("first line\nan aside {ch} continues\n");
        assert_eq!(dash_hits(&as_char), vec![(2, name)], "{name} character");
        let as_escape = format!("// a comment\nlet s = \"aside \\u{{{code:x}}} more\";\n");
        assert_eq!(dash_hits(&as_escape), vec![(2, name)], "{name} escape");
    }
    assert!(dash_hits("a hyphen-only line, with a colon: fine\n").is_empty());
}
