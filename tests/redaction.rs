//! Source-audit / redaction guard tests (SEG-13).
//!
//! These are grep-style checks over the repository's source tree: they fail
//! the build if a future change interpolates a known secret *name* into a
//! format/assert string, or reintroduces an inline `<script>` body into a
//! template (which would defeat the strict CSP).
//!
//! Unit coverage of `redact_message` itself lives next to the function in
//! `src/security.rs` (the crate is a binary, so integration tests cannot
//! call into it).

use std::fs;
use std::path::{Path, PathBuf};

const SRC_DIR: &str = "src";
const TEMPLATES_DIR: &str = "templates";
const SECRET_ENV_VARS: &[&str] = &["ENCRYPTION_KEY", "APP_PASSWORD"];

fn manifest_path(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join(rel)
}

fn walk_rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap_or_else(|e| panic!("read {:?}: {e}", dir)) {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            walk_rs_files(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
            out.push(path);
        }
    }
}

fn walk_templates(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).unwrap_or_else(|e| panic!("read {:?}: {e}", dir)) {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            walk_templates(&path, out);
        } else if path.extension().and_then(|e| e.to_str()) == Some("html") {
            out.push(path);
        }
    }
}

fn read(path: &Path) -> String {
    fs::read_to_string(path).unwrap_or_else(|e| panic!("read {:?}: {e}", path))
}

/// Does any `{...}` span on this line contain `token`? Multi-line spans are
/// deliberately out of scope for this cheap guard; the manual audit lives in
/// the segment report.
fn line_has_token_in_brace(line: &str, token: &str) -> bool {
    let bytes = line.as_bytes();
    for (i, &b) in bytes.iter().enumerate() {
        if b != b'{' {
            continue;
        }
        if let Some(rel_end) = line[i..].find('}') {
            let span = &line[i..=i + rel_end];
            if span.contains(token) {
                return true;
            }
        }
    }
    false
}

#[test]
fn no_format_string_brace_interpolates_secret_env_var_names() {
    let mut files = Vec::new();
    walk_rs_files(&manifest_path(SRC_DIR), &mut files);
    assert!(files.len() > 10, "expected to walk the source tree");
    let mut violations = Vec::new();
    for file in files {
        let content = read(&file);
        for (idx, line) in content.lines().enumerate() {
            for token in SECRET_ENV_VARS {
                if line_has_token_in_brace(line, token) {
                    violations.push(format!("{}:{}: {line}", file.display(), idx + 1));
                }
            }
        }
    }
    assert!(
        violations.is_empty(),
        "secret env var names interpolated in format-string braces:\n{}",
        violations.join("\n")
    );
}

#[test]
fn no_println_family_outside_tests_and_startup() {
    // stdout/stderr writes must not carry request data. The only legitimate
    // call sites are (a) `main.rs` startup failure before logging is up,
    // (b) `eprintln!` in test-only live-lightpanda probes.
    let mut files = Vec::new();
    walk_rs_files(&manifest_path(SRC_DIR), &mut files);
    for file in files {
        let content = read(&file);
        let mut in_tests_mod = false;
        for (idx, line) in content.lines().enumerate() {
            let trimmed = line.trim();
            if trimmed.starts_with("mod tests") {
                in_tests_mod = true;
            }
            if in_tests_mod {
                continue; // test modules may print diagnostics freely
            }
            for needle in ["println!(", "eprintln!(", "print!(", "dbg!("] {
                assert!(
                    !trimmed.contains(needle),
                    "{}:{}: {needle} outside test code: {trimmed}",
                    file.display(),
                    idx + 1
                );
            }
        }
    }
}

#[test]
fn templates_contain_no_inline_scripts() {
    let mut files = Vec::new();
    walk_templates(&manifest_path(TEMPLATES_DIR), &mut files);
    assert!(!files.is_empty(), "expected templates");
    for file in &files {
        let content = read(file);
        let mut rest = content.as_str();
        while let Some(pos) = rest.find("<script") {
            let tag_end = rest[pos..].find('>').map(|e| pos + e).unwrap_or(rest.len());
            let tag = &rest[pos..tag_end];
            assert!(
                tag.contains("src="),
                "{}: inline <script> body found: {tag}",
                file.display()
            );
            rest = &rest[tag_end..];
        }
    }
}

#[test]
fn no_inline_event_handler_attributes_in_templates() {
    let mut files = Vec::new();
    walk_templates(&manifest_path(TEMPLATES_DIR), &mut files);
    for file in &files {
        let content = read(file);
        for (idx, line) in content.lines().enumerate() {
            for needle in [
                " onclick=",
                " onerror=",
                " onload=",
                " onsubmit=",
                " onchange=",
                " oninput=",
                " hx-on:",
            ] {
                assert!(
                    !line.to_ascii_lowercase().contains(needle),
                    "{}:{}: inline handler attribute {needle}: {line}",
                    file.display(),
                    idx + 1
                );
            }
        }
    }
}

#[test]
fn layout_references_external_app_js_and_not_inline_behaviour() {
    let layout = read(&manifest_path("templates/layout.html"));
    assert!(
        layout.contains("<script src=\"/public/app.js\" defer></script>"),
        "layout.html must load /public/app.js"
    );
    assert!(
        layout.contains("<script src=\"/public/htmx.min.js\" defer></script>"),
        "layout.html must load the vendored htmx"
    );
    // Exactly the two external scripts, no third inline behaviour block.
    assert_eq!(
        layout.matches("<script").count(),
        2,
        "layout.html should contain exactly two external script tags"
    );
    // The authorized-use footer is persistent product surface.
    assert!(layout.contains("Monitor owned or authorized websites only."));
}

#[test]
fn public_app_js_exists_and_is_served_shape() {
    let js = read(&manifest_path("public/app.js"));
    assert!(js.contains("window.appToast"));
    assert!(js.contains("htmx:config:request"));
    // CSP forbids inline scripts; app.js must carry the page logic.
    assert!(js.contains("rail-toggle"));
}
