//! Portable findings reports. Captured data is always escaped in HTML.
use super::Finding;
use anyhow::{Context, Result};
use std::{io::Write, path::Path};

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}
pub fn write(path: &Path, findings: &[Finding], html: bool) -> Result<()> {
    let directory = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    let mut file = tempfile::NamedTempFile::new_in(directory)
        .with_context(|| format!("Prepare findings report {}", path.display()))?;
    if !html {
        serde_json::to_writer_pretty(
            &mut file,
            &serde_json::json!({"format":"ferrite-scanner-findings","version":1,"findings":findings}),
        )?;
    } else {
        writeln!(
            file,
            "<!doctype html><html lang=\"en\"><meta charset=\"utf-8\"><meta name=\"viewport\" content=\"width=device-width\"><meta http-equiv=\"Content-Security-Policy\" content=\"default-src 'none'; style-src 'unsafe-inline'\"><title>Ferrite scanner findings</title><style>body{{font:15px/1.55 system-ui;max-width:1100px;margin:3em auto;padding:0 1em;color:#222}}article{{border-top:1px solid #ccc;margin:2em 0}}pre{{white-space:pre-wrap;overflow-wrap:anywhere;background:#f4f4f4;padding:1em}}.High{{color:#b32624}}.Medium{{color:#995000}}.Low{{color:#806200}}.Information{{color:#18528c}}</style><h1>Ferrite scanner findings</h1><p>{} findings</p>",
            findings.len()
        )?;
        for f in findings {
            writeln!(
                file,
                "<article><h2 class=\"{}\">{} — {}</h2><p>{} · {} · {}</p><p>{} {}</p><h3>Evidence details</h3><pre>{}</pre><h3>Description</h3><p>{}</p><h3>Remediation</h3><p>{}</p><h3>Notes</h3><pre>{}</pre>",
                f.severity.label(),
                f.severity.label(),
                escape(&f.title),
                f.confidence.label(),
                escape(
                    &f.origins
                        .iter()
                        .map(|v| v.label())
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
                f.state.label(),
                escape(&f.method),
                escape(&f.url),
                escape(&f.detail),
                escape(&f.description),
                escape(&f.remediation),
                escape(&f.notes)
            )?;
            for evidence in &f.evidence {
                writeln!(
                    file,
                    "<details><summary>{}</summary><h4>Request</h4><pre>{}</pre><h4>Response</h4><pre>{}</pre></details>",
                    escape(&evidence.label),
                    escape(&String::from_utf8_lossy(&evidence.exchange.request)),
                    escape(&String::from_utf8_lossy(&evidence.exchange.response))
                )?;
            }
            writeln!(file, "</article>")?;
        }
        writeln!(file, "</html>")?;
    }
    file.flush()?;
    file.persist_noclobber(path)
        .with_context(|| format!("Create findings report {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    #[test]
    fn escape_never_embeds_captured_markup() {
        assert_eq!(
            super::escape("<script>\"&'"),
            "&lt;script&gt;&quot;&amp;&#39;"
        );
    }
}
