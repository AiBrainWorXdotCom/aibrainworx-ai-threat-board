use std::collections::{HashMap, HashSet};

use regex::Regex;
use serde_json::Value;

use crate::models::{MyStackConfig, StackComponent, StackMatchSummary, Vulnerability};
use crate::security::strip_invisible_unicode;

const MAX_COMPONENTS: usize = 5000;

/// Detects manifest/SBOM format and extracts normalized dependency components completely locally.
pub fn parse_stack_manifest(
    filename: &str,
    raw_content: &str,
) -> Result<(String, Vec<StackComponent>), String> {
    if raw_content.len() > 2 * 1024 * 1024 {
        return Err("Manifest exceeds 2 MB size limit".to_string());
    }
    let content = strip_invisible_unicode(raw_content);
    let trimmed = content.trim();
    if trimmed.is_empty() {
        return Err("Manifest content is empty".to_string());
    }

    let lower_name = filename.trim().to_ascii_lowercase();
    let src_label = if filename.trim().is_empty() {
        "pasted-manifest".to_string()
    } else {
        filename
            .trim()
            .chars()
            .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
            .take(64)
            .collect()
    };

    let (format_name, raw_components) = if trimmed.starts_with('{') {
        parse_json_manifest(&lower_name, trimmed, &src_label)?
    } else if lower_name.ends_with(".xml") || trimmed.starts_with('<') {
        ("pom.xml".to_string(), parse_pom_xml(trimmed, &src_label))
    } else if lower_name.contains("cargo.lock") || trimmed.contains("[[package]]") {
        (
            "Cargo.lock".to_string(),
            parse_cargo_lock(trimmed, &src_label),
        )
    } else if lower_name.contains("cargo.toml") {
        (
            "Cargo.toml".to_string(),
            parse_cargo_toml(trimmed, &src_label),
        )
    } else if lower_name.contains("pyproject.toml") {
        (
            "pyproject.toml".to_string(),
            parse_pyproject_toml(trimmed, &src_label),
        )
    } else if lower_name.ends_with("go.mod") || trimmed.starts_with("module ") {
        ("go.mod".to_string(), parse_go_mod(trimmed, &src_label))
    } else {
        (
            "requirements.txt".to_string(),
            parse_requirements_txt(trimmed, &src_label),
        )
    };

    let deduped = dedupe_components(raw_components);
    if deduped.is_empty() {
        return Err(format!(
            "Parsed format '{format_name}' but found zero recognizable packages"
        ));
    }

    Ok((format_name, deduped))
}

fn parse_json_manifest(
    lower_name: &str,
    trimmed: &str,
    src_label: &str,
) -> Result<(String, Vec<StackComponent>), String> {
    let val: Value =
        serde_json::from_str(trimmed).map_err(|e| format!("Invalid JSON manifest: {e}"))?;

    if val.get("bomFormat").and_then(|v| v.as_str()) == Some("CycloneDX")
        || val.get("components").and_then(|v| v.as_array()).is_some()
    {
        return Ok((
            "CycloneDX SBOM".to_string(),
            parse_cyclonedx(&val, src_label),
        ));
    }

    if val.get("spdxVersion").is_some() || val.get("packages").and_then(|v| v.as_array()).is_some()
    {
        return Ok(("SPDX SBOM".to_string(), parse_spdx(&val, src_label)));
    }

    if val.get("lockfileVersion").is_some()
        || val.get("packages").and_then(|v| v.as_object()).is_some()
        || lower_name.contains("package-lock")
    {
        return Ok((
            "package-lock.json".to_string(),
            parse_package_lock(&val, src_label),
        ));
    }

    if val.get("dependencies").is_some()
        || val.get("devDependencies").is_some()
        || lower_name.contains("package.json")
    {
        return Ok((
            "package.json".to_string(),
            parse_package_json(&val, src_label),
        ));
    }

    Err("Unrecognized JSON SBOM/manifest structure".to_string())
}

fn ecosystem_from_purl(purl: &str) -> String {
    if let Some(rest) = purl.strip_prefix("pkg:") {
        if let Some((eco, _)) = rest.split_once('/') {
            return eco.to_ascii_lowercase();
        }
    }
    "unknown".to_string()
}

fn parse_cyclonedx(val: &Value, src_label: &str) -> Vec<StackComponent> {
    let mut out = Vec::new();
    if let Some(arr) = val.get("components").and_then(|v| v.as_array()) {
        for item in arr.iter().take(MAX_COMPONENTS) {
            let name = item
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            if name.is_empty() {
                continue;
            }
            let group = item
                .get("group")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            let full_name = if !group.is_empty() && !name.contains('/') {
                format!("{group}/{name}")
            } else {
                name.to_string()
            };
            let version = item
                .get("version")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim()
                .to_string();
            let purl = item.get("purl").and_then(|v| v.as_str()).unwrap_or("");
            let ecosystem = if !purl.is_empty() {
                ecosystem_from_purl(purl)
            } else {
                "sbom".to_string()
            };
            out.push(StackComponent {
                name: full_name,
                version,
                ecosystem,
                source_file: src_label.to_string(),
            });
        }
    }
    out
}

fn parse_spdx(val: &Value, src_label: &str) -> Vec<StackComponent> {
    let mut out = Vec::new();
    if let Some(arr) = val.get("packages").and_then(|v| v.as_array()) {
        for pkg in arr.iter().take(MAX_COMPONENTS) {
            let name = pkg
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim();
            if name.is_empty() {
                continue;
            }
            let version = pkg
                .get("versionInfo")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim()
                .to_string();
            let purl = pkg
                .get("externalRefs")
                .and_then(|v| v.as_array())
                .and_then(|refs| {
                    refs.iter().find_map(|r| {
                        if r.get("referenceType").and_then(|t| t.as_str()) == Some("purl") {
                            r.get("referenceLocator").and_then(|l| l.as_str())
                        } else {
                            None
                        }
                    })
                })
                .unwrap_or("");
            let ecosystem = if !purl.is_empty() {
                ecosystem_from_purl(purl)
            } else {
                "spdx".to_string()
            };
            out.push(StackComponent {
                name: name.to_string(),
                version,
                ecosystem,
                source_file: src_label.to_string(),
            });
        }
    }
    out
}

fn parse_package_lock(val: &Value, src_label: &str) -> Vec<StackComponent> {
    let mut out = Vec::new();
    if let Some(pkgs) = val.get("packages").and_then(|v| v.as_object()) {
        for (path_key, meta) in pkgs.iter().take(MAX_COMPONENTS) {
            if path_key.is_empty() {
                continue;
            }
            let name = path_key
                .rsplit("node_modules/")
                .next()
                .unwrap_or(path_key)
                .trim();
            if name.is_empty() {
                continue;
            }
            let version = meta
                .get("version")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .trim()
                .to_string();
            out.push(StackComponent {
                name: name.to_string(),
                version,
                ecosystem: "npm".to_string(),
                source_file: src_label.to_string(),
            });
        }
    }
    if out.is_empty() {
        if let Some(deps) = val.get("dependencies").and_then(|v| v.as_object()) {
            collect_package_lock_deps(deps, src_label, &mut out);
        }
    }
    out
}

fn collect_package_lock_deps(
    deps: &serde_json::Map<String, Value>,
    src_label: &str,
    out: &mut Vec<StackComponent>,
) {
    for (name, meta) in deps {
        if out.len() >= MAX_COMPONENTS {
            break;
        }
        let version = meta
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .trim()
            .to_string();
        out.push(StackComponent {
            name: name.clone(),
            version,
            ecosystem: "npm".to_string(),
            source_file: src_label.to_string(),
        });
        if let Some(nested) = meta.get("dependencies").and_then(|v| v.as_object()) {
            collect_package_lock_deps(nested, src_label, out);
        }
    }
}

fn parse_package_json(val: &Value, src_label: &str) -> Vec<StackComponent> {
    let mut out = Vec::new();
    for section in [
        "dependencies",
        "devDependencies",
        "peerDependencies",
        "optionalDependencies",
    ] {
        if let Some(obj) = val.get(section).and_then(|v| v.as_object()) {
            for (name, ver) in obj {
                if out.len() >= MAX_COMPONENTS {
                    break;
                }
                let version = ver
                    .as_str()
                    .unwrap_or("")
                    .trim()
                    .trim_start_matches(['^', '~', '=', '>', '<', ' '])
                    .to_string();
                out.push(StackComponent {
                    name: name.clone(),
                    version,
                    ecosystem: "npm".to_string(),
                    source_file: src_label.to_string(),
                });
            }
        }
    }
    out
}

fn parse_cargo_lock(content: &str, src_label: &str) -> Vec<StackComponent> {
    let mut out = Vec::new();
    let mut cur_name: Option<String> = None;
    let mut cur_ver: Option<String> = None;

    for raw_line in content.lines() {
        let line = raw_line.trim();
        if line == "[[package]]" {
            if let Some(name) = cur_name.take() {
                out.push(StackComponent {
                    name,
                    version: cur_ver.take().unwrap_or_default(),
                    ecosystem: "cargo".to_string(),
                    source_file: src_label.to_string(),
                });
                if out.len() >= MAX_COMPONENTS {
                    break;
                }
            }
            cur_ver = None;
        } else if let Some(rest) = line.strip_prefix("name = ") {
            cur_name = Some(rest.trim_matches('"').to_string());
        } else if let Some(rest) = line.strip_prefix("version = ") {
            cur_ver = Some(rest.trim_matches('"').to_string());
        }
    }
    if let Some(name) = cur_name {
        if out.len() < MAX_COMPONENTS {
            out.push(StackComponent {
                name,
                version: cur_ver.unwrap_or_default(),
                ecosystem: "cargo".to_string(),
                source_file: src_label.to_string(),
            });
        }
    }
    out
}

fn parse_cargo_toml(content: &str, src_label: &str) -> Vec<StackComponent> {
    let mut out = Vec::new();
    let mut in_deps = false;
    let re_ver = Regex::new(r#"version\s*=\s*"([^"]+)""#).expect("valid regex");

    for raw_line in content.lines() {
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            let lower = line.to_ascii_lowercase();
            in_deps = lower.contains("dependencies");
            continue;
        }
        if !in_deps {
            continue;
        }
        if let Some((name_part, rhs)) = line.split_once('=') {
            let name = name_part.trim().trim_matches('"');
            if name.is_empty() {
                continue;
            }
            let rhs_trim = rhs.trim();
            let version = if rhs_trim.starts_with('"') {
                rhs_trim.trim_matches('"').to_string()
            } else if let Some(caps) = re_ver.captures(rhs_trim) {
                caps.get(1).map(|m| m.as_str()).unwrap_or("").to_string()
            } else {
                String::new()
            };
            out.push(StackComponent {
                name: name.to_string(),
                version,
                ecosystem: "cargo".to_string(),
                source_file: src_label.to_string(),
            });
            if out.len() >= MAX_COMPONENTS {
                break;
            }
        }
    }
    out
}

fn parse_requirements_txt(content: &str, src_label: &str) -> Vec<StackComponent> {
    let mut out = Vec::new();
    let re =
        Regex::new(r#"^([A-Za-z0-9._-]+)(?:\[[^\]]+\])?\s*(?:[=<>!~]+\s*([A-Za-z0-9.*+_!-]+))?"#)
            .expect("valid regex");

    for raw_line in content.lines() {
        let without_comment = raw_line.split('#').next().unwrap_or("").trim();
        let line = without_comment.split(';').next().unwrap_or("").trim();
        if line.is_empty() || line.starts_with('-') || line.contains("://") {
            continue;
        }
        if let Some(caps) = re.captures(line) {
            let name = caps.get(1).map(|m| m.as_str()).unwrap_or("").trim();
            if name.is_empty() {
                continue;
            }
            let version = caps
                .get(2)
                .map(|m| m.as_str().trim())
                .unwrap_or("")
                .to_string();
            out.push(StackComponent {
                name: name.to_string(),
                version,
                ecosystem: "pypi".to_string(),
                source_file: src_label.to_string(),
            });
            if out.len() >= MAX_COMPONENTS {
                break;
            }
        }
    }
    out
}

fn parse_pyproject_toml(content: &str, src_label: &str) -> Vec<StackComponent> {
    let mut out = Vec::new();
    let mut in_array = false;
    let mut in_poetry = false;
    let re_spec =
        Regex::new(r#"^([A-Za-z0-9._-]+)(?:\[[^\]]+\])?\s*(?:[=<>!~^]+\s*([A-Za-z0-9.*+_!-]+))?"#)
            .expect("valid regex");

    for raw_line in content.lines() {
        let line = raw_line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with("[tool.poetry.dependencies") || line.starts_with("[tool.poetry.group") {
            in_poetry = true;
            in_array = false;
            continue;
        } else if line.starts_with('[') && !line.contains("dependencies") {
            in_poetry = false;
        }

        if line.starts_with("dependencies") && line.contains('[') {
            in_array = !line.ends_with(']');
            for chunk in line.split('"').skip(1).step_by(2) {
                if let Some(caps) = re_spec.captures(chunk.trim()) {
                    let name = caps.get(1).map(|m| m.as_str()).unwrap_or("");
                    if !name.is_empty() {
                        out.push(StackComponent {
                            name: name.to_string(),
                            version: caps.get(2).map(|m| m.as_str()).unwrap_or("").to_string(),
                            ecosystem: "pypi".to_string(),
                            source_file: src_label.to_string(),
                        });
                    }
                }
            }
            continue;
        }

        if in_array {
            if line.contains(']') {
                in_array = false;
            }
            let cleaned = line.trim_matches([',', '"', '\'', ' ']);
            if let Some(caps) = re_spec.captures(cleaned) {
                let name = caps.get(1).map(|m| m.as_str()).unwrap_or("");
                if !name.is_empty() && name != "]" {
                    out.push(StackComponent {
                        name: name.to_string(),
                        version: caps.get(2).map(|m| m.as_str()).unwrap_or("").to_string(),
                        ecosystem: "pypi".to_string(),
                        source_file: src_label.to_string(),
                    });
                }
            }
        } else if in_poetry {
            if let Some((k, v)) = line.split_once('=') {
                let name = k.trim().trim_matches('"');
                if !name.is_empty() && name != "python" {
                    let ver = v.trim().trim_matches(['"', '^', '~', ' ']).to_string();
                    out.push(StackComponent {
                        name: name.to_string(),
                        version: ver,
                        ecosystem: "pypi".to_string(),
                        source_file: src_label.to_string(),
                    });
                }
            }
        }
    }
    out
}

fn parse_go_mod(content: &str, src_label: &str) -> Vec<StackComponent> {
    let mut out = Vec::new();
    let mut in_block = false;
    for raw_line in content.lines() {
        let line = raw_line.split("//").next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with("require (") {
            in_block = true;
            continue;
        }
        if in_block && line == ")" {
            in_block = false;
            continue;
        }
        let candidate = if in_block {
            line
        } else if let Some(rest) = line.strip_prefix("require ") {
            rest.trim()
        } else {
            continue;
        };

        let parts: Vec<&str> = candidate.split_whitespace().collect();
        if !parts.is_empty() {
            let name = parts[0].trim();
            let version = parts.get(1).copied().unwrap_or("").trim().to_string();
            if !name.is_empty() {
                out.push(StackComponent {
                    name: name.to_string(),
                    version,
                    ecosystem: "golang".to_string(),
                    source_file: src_label.to_string(),
                });
            }
        }
    }
    out
}

fn parse_pom_xml(content: &str, src_label: &str) -> Vec<StackComponent> {
    let mut out = Vec::new();
    let re_dep = Regex::new(r"(?is)<dependency>(.*?)</dependency>").expect("valid regex");
    let re_group = Regex::new(r"(?is)<groupId>\s*([^<\s]+)\s*</groupId>").expect("valid regex");
    let re_artifact =
        Regex::new(r"(?is)<artifactId>\s*([^<\s]+)\s*</artifactId>").expect("valid regex");
    let re_ver = Regex::new(r"(?is)<version>\s*([^<\s]+)\s*</version>").expect("valid regex");

    for dep_cap in re_dep.captures_iter(content).take(MAX_COMPONENTS) {
        let block = dep_cap.get(1).map(|m| m.as_str()).unwrap_or("");
        let group = re_group
            .captures(block)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().trim())
            .unwrap_or("");
        let artifact = re_artifact
            .captures(block)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().trim())
            .unwrap_or("");
        if artifact.is_empty() {
            continue;
        }
        let version = re_ver
            .captures(block)
            .and_then(|c| c.get(1))
            .map(|m| m.as_str().trim())
            .unwrap_or("")
            .to_string();
        let name = if group.is_empty() {
            artifact.to_string()
        } else {
            format!("{group}:{artifact}")
        };
        out.push(StackComponent {
            name,
            version,
            ecosystem: "maven".to_string(),
            source_file: src_label.to_string(),
        });
    }
    out
}

fn dedupe_components(items: Vec<StackComponent>) -> Vec<StackComponent> {
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    for item in items {
        let key = (
            item.ecosystem.to_ascii_lowercase(),
            item.name.to_ascii_lowercase(),
            item.version.to_ascii_lowercase(),
        );
        if seen.insert(key) {
            out.push(item);
            if out.len() >= MAX_COMPONENTS {
                break;
            }
        }
    }
    out
}

/// Checks whether needle appears on ASCII alphanumeric boundaries inside haystack.
fn contains_token_boundary(haystack_lower: &str, needle_lower: &str) -> bool {
    if needle_lower.is_empty() || haystack_lower.len() < needle_lower.len() {
        return false;
    }
    let h_bytes = haystack_lower.as_bytes();
    let mut start = 0;
    while let Some(pos) = haystack_lower[start..].find(needle_lower) {
        let abs_pos = start + pos;
        let end_pos = abs_pos + needle_lower.len();
        let left_ok = abs_pos == 0 || !h_bytes[abs_pos - 1].is_ascii_alphanumeric();
        let right_ok = end_pos >= h_bytes.len() || !h_bytes[end_pos].is_ascii_alphanumeric();
        if left_ok && right_ok {
            return true;
        }
        start = abs_pos + needle_lower.len();
    }
    false
}

/// Correlates tracked vulnerabilities against the user's configured My Stack inventory.
pub fn correlate_stack(
    vulns: &mut HashMap<String, Vulnerability>,
    config: &MyStackConfig,
) -> StackMatchSummary {
    let watch_terms: Vec<(String, String)> = config
        .vendors
        .iter()
        .chain(config.products.iter())
        .chain(config.keywords.iter())
        .map(|s| s.trim())
        .filter(|s| s.len() >= 2)
        .map(|s| (s.to_string(), s.to_ascii_lowercase()))
        .collect();

    // Precompute component search aliases (e.g. `@scope/pkg` -> `pkg`, `github.com/org/repo` -> `repo`)
    let mut comp_terms: Vec<(String, String)> = Vec::new();
    let mut seen_comp = HashSet::new();
    for c in &config.components {
        let full_lower = c.name.trim().to_ascii_lowercase();
        let short_name = full_lower
            .rsplit(['/', ':'])
            .next()
            .unwrap_or(&full_lower)
            .to_string();
        for term in [full_lower, short_name] {
            if term.len() >= 3 && seen_comp.insert(term.clone()) {
                comp_terms.push((c.name.clone(), term));
            }
        }
    }

    let configured = !watch_terms.is_empty() || !config.components.is_empty();
    let mut matched_vuln_count = 0usize;
    let mut matched_kev_count = 0usize;
    let mut top_hits: Vec<(u8, String)> = Vec::new();

    for v in vulns.values_mut() {
        if !configured {
            v.matched_stack.clear();
            continue;
        }

        let vendor_l = v.vendor.as_deref().unwrap_or("").to_ascii_lowercase();
        let product_l = v.product.as_deref().unwrap_or("").to_ascii_lowercase();
        let text_l = format!("{} {} {}", v.title, v.description, product_l).to_ascii_lowercase();

        let mut hits: Vec<String> = Vec::new();
        let mut seen_labels = HashSet::new();

        for (display, term) in &watch_terms {
            let is_match = vendor_l == *term
                || product_l == *term
                || contains_token_boundary(&vendor_l, term)
                || contains_token_boundary(&product_l, term)
                || (term.len() >= 3 && contains_token_boundary(&text_l, term));
            if is_match && seen_labels.insert(display.to_ascii_lowercase()) {
                hits.push(display.clone());
                if hits.len() >= 6 {
                    break;
                }
            }
        }

        if hits.len() < 6 {
            for (display, term) in &comp_terms {
                let is_match = vendor_l == *term
                    || product_l == *term
                    || contains_token_boundary(&product_l, term)
                    || (term.len() >= 4 && contains_token_boundary(&text_l, term));
                if is_match && seen_labels.insert(display.to_ascii_lowercase()) {
                    hits.push(display.clone());
                    if hits.len() >= 6 {
                        break;
                    }
                }
            }
        }

        v.matched_stack = hits;
        if !v.matched_stack.is_empty() {
            matched_vuln_count += 1;
            if v.is_kev {
                matched_kev_count += 1;
            }
            top_hits.push((v.ai_risk_score, v.id.clone()));
        }
    }

    top_hits.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
    let top_matched_cves = top_hits.into_iter().take(12).map(|(_, id)| id).collect();

    StackMatchSummary {
        configured,
        component_count: config.components.len(),
        vendor_watch_count: watch_terms.len(),
        matched_vuln_count,
        matched_kev_count,
        top_matched_cves,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::{Severity, TriageStatus};
    use chrono::Utc;

    #[test]
    fn parses_cyclonedx_package_lock_cargo_lock_requirements_gomod_pom() {
        let cdx = r#"{"bomFormat":"CycloneDX","components":[{"name":"openssl","version":"3.0.12","purl":"pkg:deb/debian/openssl@3.0.12"}]}"#;
        let (fmt, comps) = parse_stack_manifest("bom.json", cdx).unwrap();
        assert_eq!(fmt, "CycloneDX SBOM");
        assert_eq!(comps[0].name, "openssl");

        let pkg_lock = r#"{"lockfileVersion":3,"packages":{"":{"name":"app"},"node_modules/axios":{"version":"1.6.8"}}}"#;
        let (fmt, comps) = parse_stack_manifest("package-lock.json", pkg_lock).unwrap();
        assert_eq!(fmt, "package-lock.json");
        assert_eq!(comps[0].name, "axios");
        assert_eq!(comps[0].ecosystem, "npm");

        let cargo_lock = "[[package]]\nname = \"tokio\"\nversion = \"1.40.0\"\n";
        let (fmt, comps) = parse_stack_manifest("Cargo.lock", cargo_lock).unwrap();
        assert_eq!(fmt, "Cargo.lock");
        assert_eq!(comps[0].name, "tokio");

        let reqs =
            "# comment\nfastapi==0.115.0\nuvicorn[standard]>=0.30.0 ; python_version >= '3.10'\n";
        let (fmt, comps) = parse_stack_manifest("requirements.txt", reqs).unwrap();
        assert_eq!(fmt, "requirements.txt");
        assert_eq!(comps.len(), 2);
        assert_eq!(comps[0].name, "fastapi");

        let gomod =
            "module example.com/app\ngo 1.23\nrequire (\n    golang.org/x/crypto v0.27.0\n)\n";
        let (fmt, comps) = parse_stack_manifest("go.mod", gomod).unwrap();
        assert_eq!(fmt, "go.mod");
        assert_eq!(comps[0].name, "golang.org/x/crypto");

        let pom = "<project><dependencies><dependency><groupId>org.apache.logging.log4j</groupId><artifactId>log4j-core</artifactId><version>2.14.1</version></dependency></dependencies></project>";
        let (fmt, comps) = parse_stack_manifest("pom.xml", pom).unwrap();
        assert_eq!(fmt, "pom.xml");
        assert_eq!(comps[0].name, "org.apache.logging.log4j:log4j-core");
    }

    #[test]
    fn stack_correlation_matches_precisely_without_short_false_positives() {
        let now = Utc::now();
        let mut vulns = HashMap::new();
        vulns.insert(
            "CVE-2026-1001".to_string(),
            Vulnerability {
                id: "CVE-2026-1001".into(),
                aliases: vec![],
                title: "Axios SSRF in proxy handling".into(),
                description: "Improper URL parsing in axios client".into(),
                severity: Severity::High,
                cvss_score: Some(8.2),
                cvss_vector: None,
                epss_score: Some(0.12),
                epss_percentile: None,
                ai_risk_score: 75,
                ai_score_factors: vec![],
                ai_summary: String::new(),
                is_kev: true,
                kev_date_added: None,
                kev_due_date: None,
                kev_required_action: None,
                forensic_triage: None,
                ransomware_use: false,
                has_public_exploit: false,
                is_ai_related: false,
                vendor: Some("axios".into()),
                product: Some("axios".into()),
                ecosystem: Some("npm".into()),
                patched_version: None,
                cwes: vec![],
                mitre_tactics: vec![],
                attack_vectors: vec![],
                sources: vec![],
                references: vec![],
                published_at: now,
                updated_at: now,
                first_seen_at: now,
                epss_delta_24h: None,
                epss_delta_7d: None,
                epss_spike: false,
                kev_days_remaining: None,
                matched_stack: vec![],
                triage_status: TriageStatus::New,
                triage_notes: String::new(),
            },
        );
        vulns.insert(
            "CVE-2026-1002".to_string(),
            Vulnerability {
                id: "CVE-2026-1002".into(),
                aliases: vec![],
                title: "Unrelated Router Issue".into(),
                description: "Stack buffer issue in embedded firmware".into(),
                severity: Severity::Medium,
                cvss_score: Some(5.5),
                cvss_vector: None,
                epss_score: None,
                epss_percentile: None,
                ai_risk_score: 40,
                ai_score_factors: vec![],
                ai_summary: String::new(),
                is_kev: false,
                kev_date_added: None,
                kev_due_date: None,
                kev_required_action: None,
                forensic_triage: None,
                ransomware_use: false,
                has_public_exploit: false,
                is_ai_related: false,
                vendor: Some("mikrotik".into()),
                product: Some("routeros".into()),
                ecosystem: None,
                patched_version: None,
                cwes: vec![],
                mitre_tactics: vec![],
                attack_vectors: vec![],
                sources: vec![],
                references: vec![],
                published_at: now,
                updated_at: now,
                first_seen_at: now,
                epss_delta_24h: None,
                epss_delta_7d: None,
                epss_spike: false,
                kev_days_remaining: None,
                matched_stack: vec![],
                triage_status: TriageStatus::New,
                triage_notes: String::new(),
            },
        );

        let stack = MyStackConfig {
            vendors: vec!["Fortinet".into()],
            products: vec![],
            keywords: vec![],
            components: vec![
                StackComponent {
                    name: "axios".into(),
                    version: "1.6.8".into(),
                    ecosystem: "npm".into(),
                    source_file: "package-lock.json".into(),
                },
                StackComponent {
                    name: "go".into(),
                    version: "1.22".into(),
                    ecosystem: "golang".into(),
                    source_file: "go.mod".into(),
                },
            ],
            updated_at: Some(now),
        };

        let summary = correlate_stack(&mut vulns, &stack);
        assert_eq!(summary.matched_vuln_count, 1);
        assert_eq!(summary.matched_kev_count, 1);
        assert_eq!(vulns["CVE-2026-1001"].matched_stack, vec!["axios"]);
        assert!(vulns["CVE-2026-1002"].matched_stack.is_empty());
    }
}
