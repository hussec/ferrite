use crate::{
    http::Message,
    model::{ReplaceRule, RuleTarget},
};
use anyhow::Result;

pub fn apply(msg: &mut Message, rules: &[ReplaceRule], response: bool) -> Result<()> {
    let mut body_changed = false;
    for r in rules.iter().filter(|r| r.enabled) {
        let header = matches!(
            r.target,
            RuleTarget::RequestHeader | RuleTarget::ResponseHeader
        );
        if response
            != matches!(
                r.target,
                RuleTarget::ResponseHeader | RuleTarget::ResponseBody
            )
        {
            continue;
        }
        if header {
            if r.pattern.is_empty() {
                if !r.replacement.is_empty() {
                    msg.headers.push(parse_header(&r.replacement)?);
                }
                continue;
            }
            let mut out = Vec::new();
            for (k, v) in &msg.headers {
                let original = format!("{k}: {v}");
                let value = replace(original.as_bytes(), r)?;
                if !value.is_empty() {
                    out.push(parse_header(std::str::from_utf8(&value)?)?);
                }
            }
            msg.headers = out;
        } else {
            let body = replace(&msg.body, r)?;
            body_changed |= body != msg.body;
            msg.body = body;
        }
    }
    if body_changed {
        msg.normalize_length();
    }
    Ok(())
}
fn parse_header(value: &str) -> Result<(String, String)> {
    anyhow::ensure!(
        !value.contains(['\r', '\n', '\0']),
        "Replacement header must contain one line"
    );
    let (k, v) = value
        .split_once(':')
        .ok_or_else(|| anyhow::anyhow!("Replacement header needs a colon"))?;
    anyhow::ensure!(
        !k.is_empty()
            && k.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)),
        "Invalid replacement header name"
    );
    Ok((k.into(), v.trim().into()))
}
fn replace(bytes: &[u8], r: &ReplaceRule) -> Result<Vec<u8>> {
    if r.regex {
        Ok(regex::bytes::RegexBuilder::new(&r.pattern)
            .dot_matches_new_line(true)
            .build()?
            .replace_all(bytes, r.replacement.as_bytes())
            .into_owned())
    } else {
        if r.pattern.is_empty() {
            return Ok(bytes.to_vec());
        }
        let pat = r.pattern.as_bytes();
        let mut out = Vec::new();
        let mut at = 0;
        while at < bytes.len() {
            if bytes[at..].starts_with(pat) {
                out.extend_from_slice(r.replacement.as_bytes());
                at += pat.len();
            } else {
                out.push(bytes[at]);
                at += 1;
            }
        }
        Ok(out)
    }
}
