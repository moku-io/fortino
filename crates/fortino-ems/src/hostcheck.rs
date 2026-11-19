//! Host-verification evaluation: turns `hv.conf` rules into the `RULES` bitstring.
//!
//! Results are truthful. A feature Fortino can check is checked; a feature that describes
//! software Fortino is not (antivirus) is evaluated as absent; any other feature never matches,
//! whatever its `negative` flag says, so an unknown check can never earn a tag.

use fortino_platform::facts::Facts;
use fortino_proto_ems::hv::{Criterion, HostRules, Rule};
use fortino_proto_ems::tags::Bits;

/// The `<os>` value rules use for this platform.
pub fn rule_os() -> &'static str {
    if cfg!(target_os = "macos") {
        "mac"
    } else {
        "linux"
    }
}

/// macOS marketing names by major version.
fn codename(major: u32, minor: u32) -> Option<&'static str> {
    Some(match (major, minor) {
        (10, 12) => "Sierra",
        (10, 13) => "High Sierra",
        (10, 14) => "Mojave",
        (10, 15) => "Catalina",
        (11, _) => "Big Sur",
        (12, _) => "Monterey",
        (13, _) => "Ventura",
        (14, _) => "Sonoma",
        (15, _) => "Sequoia",
        (26, _) => "Tahoe",
        _ => return None,
    })
}

fn version_numbers(s: &str) -> Vec<u32> {
    s.split('.').map_while(|p| p.trim().parse().ok()).collect()
}

/// The OS as rules may name it.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Os {
    version: Vec<u32>,
    names: Vec<String>,
}

fn os_of(f: &Facts) -> Os {
    let v = f
        .os_version
        .rsplit(' ')
        .next()
        .unwrap_or_default()
        .to_owned();
    let version = version_numbers(&v);
    let major = version.first().copied().unwrap_or(0);
    let minor = version.get(1).copied().unwrap_or(0);
    let mut names = vec![v.clone(), f.os_version.clone(), major.to_string()];
    if major == 10 {
        names.push(format!("10.{minor}"));
    }
    if let Some(c) = codename(major, minor) {
        for prefix in ["", "macOS ", "Mac OS X ", "OS X "] {
            names.push(format!("{prefix}{c}"));
        }
    }
    Os {
        version,
        names: names.into_iter().map(|n| n.to_ascii_lowercase()).collect(),
    }
}

fn cmp_versions(a: &[u32], b: &[u32]) -> std::cmp::Ordering {
    let n = a.len().max(b.len());
    (0..n)
        .map(|i| {
            a.get(i)
                .copied()
                .unwrap_or(0)
                .cmp(&b.get(i).copied().unwrap_or(0))
        })
        .find(|o| o.is_ne())
        .unwrap_or(std::cmp::Ordering::Equal)
}

// UNVERIFIED: `os_version` content format. One deployment uses operator `=` with one
// rule per macOS release name; numeric comparisons are supported for versions.
fn os_matches(os: &Os, c: &Criterion) -> bool {
    let content = c.content.trim().to_ascii_lowercase();
    let wanted = version_numbers(content.trim_start_matches("macos ").trim());
    let ord = (!wanted.is_empty())
        .then(|| cmp_versions(&os.version[..wanted.len().min(os.version.len())], &wanted));
    match c.operator.trim() {
        ">=" => ord.is_some_and(|o| o.is_ge()),
        ">" => ord.is_some_and(|o| o.is_gt()),
        "<=" => ord.is_some_and(|o| o.is_le()),
        "<" => ord.is_some_and(|o| o.is_lt()),
        "!=" | "<>" => !os.names.contains(&content),
        _ => os.names.contains(&content),
    }
}

/// How one criterion evaluates.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Outcome {
    /// Checked; `negative` applies.
    Known(bool),
    /// Not checkable: never matches.
    Unknown,
}

fn criterion(feature: &str, os: &Os, c: &Criterion) -> Outcome {
    match feature {
        "os_version" => Outcome::Known(os_matches(os, c)),
        // Fortino is not an antivirus and installs none: every antivirus predicate is false.
        "antivirus" => Outcome::Known(false),
        _ => Outcome::Unknown,
    }
}

/// Whether a rule matches. All criteria must hold.
// UNVERIFIED: AND across criteria within a rule.
pub fn rule_matches(rule: &Rule, facts: &Facts) -> bool {
    if !rule.os.eq_ignore_ascii_case(rule_os()) || rule.criteria.is_empty() {
        return false;
    }
    let os = os_of(facts);
    rule.criteria.iter().all(|cs| {
        !cs.criteria.is_empty()
            && cs
                .criteria
                .iter()
                .all(|c| match criterion(&cs.feature, &os, c) {
                    Outcome::Known(v) => v != c.negative,
                    Outcome::Unknown => false,
                })
    })
}

/// The `RULES` bitstring: `max_rule_flag + 1` bits, set for each matching rule.
pub fn evaluate(rules: &HostRules, facts: &Facts) -> Bits {
    let mut bits = Bits::zeros(rules.max_rule_flag + 1);
    for r in &rules.rules {
        if rule_matches(r, facts) {
            bits.set(r.flag, true);
        }
    }
    bits
}

#[cfg(test)]
mod tests {
    use super::*;
    use fortino_proto_ems::hv::Criteria;

    fn facts(v: &str) -> Facts {
        Facts {
            os_version: format!("macOS {v}"),
            ..Facts::default()
        }
    }

    fn rule(feature: &str, content: &str, op: &str, negative: bool) -> Rule {
        Rule {
            flag: 1,
            name: "r".into(),
            os: rule_os().into(),
            criteria: vec![Criteria {
                feature: feature.into(),
                criteria: vec![Criterion {
                    content: content.into(),
                    negative,
                    operator: op.into(),
                }],
            }],
            tag: None,
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn os_version_by_name_and_number() {
        let f = facts("15.6.1");
        assert!(rule_matches(
            &rule("os_version", "macOS Sequoia", "=", false),
            &f
        ));
        assert!(rule_matches(&rule("os_version", "Sequoia", "=", false), &f));
        assert!(!rule_matches(
            &rule("os_version", "macOS Sonoma", "=", false),
            &f
        ));
        assert!(!rule_matches(
            &rule("os_version", "macOS Sequoia", "=", false),
            &facts("26.1")
        ));
        assert!(rule_matches(&rule("os_version", "15", ">=", false), &f));
        assert!(rule_matches(&rule("os_version", "15.6", ">=", false), &f));
        assert!(!rule_matches(&rule("os_version", "15.7", ">=", false), &f));
        assert!(rule_matches(
            &rule("os_version", "macOS Sonoma", "=", true),
            &f
        ));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn never_claims_unknown_features() {
        let f = facts("15.6.1");
        assert!(!rule_matches(&rule("sandbox", "x", "", false), &f));
        assert!(!rule_matches(&rule("sandbox", "x", "", true), &f));
        assert!(!rule_matches(
            &rule("cve_vulnerabilities", "critical", "", true),
            &f
        ));
        // No antivirus: "AV enabled" is false, so only its negation matches.
        assert!(!rule_matches(
            &rule("antivirus", "AV enabled", "", false),
            &f
        ));
        assert!(rule_matches(&rule("antivirus", "AV enabled", "", true), &f));
    }

    #[test]
    fn other_os_rules_never_match() {
        let mut r = rule("os_version", "macOS Sequoia", "=", true);
        r.os = "windows".into();
        assert!(!rule_matches(&r, &facts("15.6.1")));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn bitstring_is_indexed_by_flag() {
        let mut a = rule("os_version", "Sequoia", "=", false);
        a.flag = 3;
        let rules = HostRules {
            max_rule_flag: 4,
            rules: vec![a, rule("sandbox", "x", "", false)],
            ..HostRules::default()
        };
        assert_eq!(evaluate(&rules, &facts("15.6.1")).to_string(), "00010");
    }
}
