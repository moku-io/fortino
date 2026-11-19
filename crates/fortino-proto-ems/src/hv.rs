//! Host-verification rules.
//!
//! ```xml
//! <forticlient_configuration><host_verification><max_tag_flag/><max_rule_flag/>
//!  <rules><rule><rule_flag>N</rule_flag><name/><os>mac</os>
//!   <criteria><feature>os_version</feature>
//!    <criterion><content/><negative>0|1</negative><operator/></criterion></criteria>
//!   <tag><tag_name/><tag_flag>M</tag_flag></tag></rule></rules>
//!  <tags><tag><tag_flag/><tag_name/></tag></tags></host_verification></forticlient_configuration>
//! ```
//!
//! The client evaluates every rule for its OS into a `RULES` bitstring indexed by `rule_flag`.

use quick_xml::Reader;
use quick_xml::events::Event;

/// Most rules accepted.
pub const MAX_RULES: usize = 2048;
/// Highest flag accepted.
pub const MAX_FLAG: usize = 4095;

/// One criterion.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Criterion {
    /// Value to compare against.
    pub content: String,
    /// Invert the result.
    pub negative: bool,
    /// Comparison (`=`, `>=`, …); may be empty.
    pub operator: String,
}

/// A feature and its criteria.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Criteria {
    /// `os_version`, `antivirus`, `process`, …
    pub feature: String,
    /// Criteria for that feature.
    pub criteria: Vec<Criterion>,
}

/// One rule.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Rule {
    /// Bit in `RULES`.
    pub flag: usize,
    /// Name.
    pub name: String,
    /// `mac`, `windows`, `linux`, `ios`.
    pub os: String,
    /// Feature checks.
    pub criteria: Vec<Criteria>,
    /// Tag the rule grants, if named.
    pub tag: Option<(String, usize)>,
}

/// A parsed `hv.conf`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostRules {
    /// `max_rule_flag`.
    pub max_rule_flag: usize,
    /// `max_tag_flag`.
    pub max_tag_flag: usize,
    /// Rules.
    pub rules: Vec<Rule>,
    /// Tag names by flag.
    pub tags: Vec<(usize, String)>,
}

/// Errors parsing `hv.conf`.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HvError {
    /// Not well-formed XML.
    #[error("malformed host-verification rules: {0}")]
    Xml(String),
    /// A flag is missing, not a number, or out of range.
    #[error("bad flag in host-verification rules")]
    Flag,
    /// Too many rules.
    #[error("too many host-verification rules")]
    TooMany,
}

fn flag(s: &str) -> Result<usize, HvError> {
    s.trim()
        .parse::<usize>()
        .ok()
        .filter(|f| *f <= MAX_FLAG)
        .ok_or(HvError::Flag)
}

/// Parses `hv.conf`.
pub fn parse(xml: &str) -> Result<HostRules, HvError> {
    let mut r = Reader::from_str(xml);
    let mut path: Vec<String> = Vec::new();
    let mut out = HostRules::default();
    let mut rule: Option<Rule> = None;
    let mut criteria: Option<Criteria> = None;
    let mut criterion: Option<Criterion> = None;
    let mut tag_name = String::new();
    let mut tag_flag: Option<usize> = None;
    loop {
        let ev = r.read_event().map_err(|e| HvError::Xml(e.to_string()))?;
        match ev {
            Event::Start(e) => {
                let name = String::from_utf8_lossy(e.name().as_ref()).into_owned();
                match name.as_str() {
                    "rule" => {
                        if out.rules.len() == MAX_RULES {
                            return Err(HvError::TooMany);
                        }
                        rule = Some(Rule::default());
                    }
                    "criteria" if rule.is_some() => criteria = Some(Criteria::default()),
                    "criterion" if criteria.is_some() => criterion = Some(Criterion::default()),
                    "tag" => {
                        tag_name.clear();
                        tag_flag = None;
                    }
                    _ => {}
                }
                if path.len() > 32 {
                    return Err(HvError::Xml("nested too deeply".into()));
                }
                path.push(name);
            }
            Event::End(_) => {
                let Some(name) = path.pop() else {
                    return Err(HvError::Xml("unbalanced".into()));
                };
                match name.as_str() {
                    "criterion" => {
                        if let (Some(c), Some(cs)) = (criterion.take(), criteria.as_mut()) {
                            cs.criteria.push(c);
                        }
                    }
                    "criteria" => {
                        if let (Some(cs), Some(r)) = (criteria.take(), rule.as_mut()) {
                            r.criteria.push(cs);
                        }
                    }
                    "rule" => {
                        if let Some(r) = rule.take() {
                            out.rules.push(r);
                        }
                    }
                    "tag" => {
                        let t = tag_flag.take();
                        match (rule.as_mut(), t) {
                            (Some(r), Some(f)) => r.tag = Some((tag_name.clone(), f)),
                            (None, Some(f)) => out.tags.push((f, tag_name.clone())),
                            _ => {}
                        }
                    }
                    _ => {}
                }
            }
            Event::Text(t) => {
                let text = t
                    .unescape()
                    .map_err(|e| HvError::Xml(e.to_string()))?
                    .into_owned();
                set_text(
                    &path,
                    &text,
                    &mut out,
                    rule.as_mut(),
                    criteria.as_mut(),
                    criterion.as_mut(),
                    &mut tag_name,
                    &mut tag_flag,
                )?;
            }
            Event::CData(t) => {
                let text = String::from_utf8_lossy(&t).into_owned();
                set_text(
                    &path,
                    &text,
                    &mut out,
                    rule.as_mut(),
                    criteria.as_mut(),
                    criterion.as_mut(),
                    &mut tag_name,
                    &mut tag_flag,
                )?;
            }
            Event::Eof => break,
            _ => {}
        }
    }
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
fn set_text(
    path: &[String],
    text: &str,
    out: &mut HostRules,
    rule: Option<&mut Rule>,
    criteria: Option<&mut Criteria>,
    criterion: Option<&mut Criterion>,
    tag_name: &mut String,
    tag_flag: &mut Option<usize>,
) -> Result<(), HvError> {
    let Some(leaf) = path.last() else {
        return Ok(());
    };
    let parent = path.len().checked_sub(2).and_then(|i| path.get(i));
    match (parent.map(String::as_str), leaf.as_str()) {
        (Some("host_verification"), "max_rule_flag") => out.max_rule_flag = flag(text)?,
        (Some("host_verification"), "max_tag_flag") => out.max_tag_flag = flag(text)?,
        (Some("criterion"), "content") => {
            if let Some(c) = criterion {
                c.content.push_str(text);
            }
        }
        (Some("criterion"), "negative") => {
            if let Some(c) = criterion {
                c.negative = text.trim() == "1";
            }
        }
        (Some("criterion"), "operator") => {
            if let Some(c) = criterion {
                c.operator = text.trim().to_owned();
            }
        }
        (Some("criteria"), "feature") => {
            if let Some(c) = criteria {
                c.feature = text.trim().to_owned();
            }
        }
        (Some("tag"), "tag_name") => tag_name.push_str(text.trim()),
        (Some("tag"), "tag_flag") => *tag_flag = Some(flag(text)?),
        (Some("rule"), field) => {
            if let Some(r) = rule {
                match field {
                    "rule_flag" => r.flag = flag(text)?,
                    "name" => r.name = text.trim().to_owned(),
                    "os" => r.os = text.trim().to_owned(),
                    _ => {}
                }
            }
        }
        _ => {}
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const XML: &str = r#"<?xml version="1.0"?>
<forticlient_configuration><version>1</version><partial_configuration>1</partial_configuration>
<host_verification><max_tag_flag>9</max_tag_flag><max_rule_flag>2</max_rule_flag>
<rules>
 <rule><rule_flag>1</rule_flag><name>TAG-MAC</name><os>mac</os>
  <criteria><feature>os_version</feature>
   <criterion><content>macOS Sequoia</content><negative>0</negative><operator>=</operator></criterion>
  </criteria>
  <tag><tag_name>TAG-OS-OK</tag_name><tag_flag>8</tag_flag></tag></rule>
 <rule><rule_flag>2</rule_flag><name>NO-AV</name><os>mac</os>
  <criteria><feature>antivirus</feature>
   <criterion><content>AV enabled</content><negative>1</negative><operator/></criterion>
  </criteria>
  <tag><tag_name>TAG-NO-AV</tag_name><tag_flag>9</tag_flag></tag></rule>
</rules>
<tags><tag><tag_flag>8</tag_flag><tag_name>TAG-OS-OK</tag_name></tag></tags>
</host_verification></forticlient_configuration>"#;

    #[test]
    fn parses_rules() {
        let h = parse(XML).unwrap();
        assert_eq!(h.max_rule_flag, 2);
        assert_eq!(h.max_tag_flag, 9);
        assert_eq!(h.rules.len(), 2);
        let r = &h.rules[0];
        assert_eq!((r.flag, r.os.as_str()), (1, "mac"));
        assert_eq!(r.criteria[0].feature, "os_version");
        assert_eq!(r.criteria[0].criteria[0].content, "macOS Sequoia");
        assert_eq!(r.tag, Some(("TAG-OS-OK".into(), 8)));
        assert!(h.rules[1].criteria[0].criteria[0].negative);
        assert_eq!(h.tags, vec![(8, "TAG-OS-OK".into())]);
    }

    #[test]
    fn rejects_bad_flags() {
        assert_eq!(
            parse("<host_verification><max_rule_flag>99999</max_rule_flag></host_verification>"),
            Err(HvError::Flag)
        );
    }
}
