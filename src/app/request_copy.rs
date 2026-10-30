//! Clipboard representations of a captured or currently edited request.
use crate::{http::Message, model::Exchange};
use anyhow::{Result, ensure};
use std::fmt::Write as _;

fn request(flow: &Exchange) -> Result<Message> {
    let mut request = Message::parse(&flow.request)?;
    let parts: Vec<_> = request.start.split_whitespace().collect();
    ensure!(
        parts.len() == 3
            && !parts[0].starts_with("HTTP/")
            && parts[0]
                .bytes()
                .all(|b| b.is_ascii_alphabetic() || b == b'-'),
        "Cannot copy an invalid HTTP request"
    );
    ensure!(!flow.url.contains('\0'), "Cannot copy a URL containing NUL");
    // Bodies in the workbench are already dechunked. Recompute framing, including
    // when the user has edited a body without updating its Content-Length.
    request.normalize_length();
    Ok(request)
}

fn shell_quote(text: &str) -> String {
    format!("'{}'", text.replace('\'', "'\"'\"'"))
}

pub(super) fn curl(flow: &Exchange) -> Result<String> {
    let request = request(flow)?;
    let version = match request.start.split_whitespace().last() {
        Some("HTTP/1.0") => "--http1.0",
        Some("HTTP/2" | "HTTP/2.0") => "--http2",
        _ => "--http1.1",
    };
    let mut command = format!(
        "curl --globoff --path-as-is {version} \\\n  --request {} \\\n  --url {}",
        shell_quote(request.method()),
        shell_quote(&flow.url),
    );
    for (name, value) in &request.headers {
        // curl uses a semicolon to send an empty header; a colon suppresses it.
        let header = if value.is_empty() {
            format!("{name};")
        } else {
            format!("{name}: {value}")
        };
        write!(command, " \\\n  --header {}", shell_quote(&header))?;
    }
    // Suppress curl's defaults when the original request omitted these headers.
    for name in ["Accept", "User-Agent", "Content-Type"] {
        if request.header(name).is_none() {
            write!(
                command,
                " \\\n  --header {}",
                shell_quote(&format!("{name}:"))
            )?;
        }
    }
    if !request.body.is_empty() {
        match std::str::from_utf8(&request.body) {
            Ok(body) if !body.contains(['\0', '\r']) && !body.starts_with('@') => {
                write!(command, " \\\n  --data-binary {}", shell_quote(body))?;
            }
            _ => {
                // POSIX printf %b decodes octal without putting NUL in argv or
                // relying on bash-specific quoting or a separate payload file.
                let mut octal = String::new();
                for byte in &request.body {
                    write!(octal, "\\0{byte:03o}")?;
                }
                command = format!(
                    "printf '%b' {} | {command} \\\n  --data-binary @-",
                    shell_quote(&octal),
                );
            }
        }
    }
    Ok(command)
}

fn python_string(text: &str) -> String {
    // JSON string escapes are also valid in a Python string literal.
    serde_json::to_string(text).expect("serializing a string cannot fail")
}

fn python_bytes(bytes: &[u8]) -> String {
    let mut literal = String::from("b'");
    for byte in bytes {
        match byte {
            b'\'' => literal.push_str("\\'"),
            b'\\' => literal.push_str("\\\\"),
            b'\r' => literal.push_str("\\r"),
            b'\n' => literal.push_str("\\n"),
            b'\t' => literal.push_str("\\t"),
            0x20..=0x7e => literal.push(*byte as char),
            _ => write!(literal, "\\x{byte:02x}").unwrap(),
        }
    }
    literal.push('\'');
    literal
}

pub(super) fn python(flow: &Exchange) -> Result<String> {
    let request = request(flow)?;
    let mut script = format!(
        "import requests\nfrom urllib3 import HTTPHeaderDict\n\nurl = {}\nbody = {}\nheaders = HTTPHeaderDict()\n",
        python_string(&flow.url),
        python_bytes(&request.body),
    );
    for (name, value) in &request.headers {
        writeln!(
            script,
            "headers.add({}, {})",
            python_string(name),
            python_string(value),
        )?;
    }
    write!(
        script,
        concat!(
            "\nprepared = requests.Request(method={}, url=url).prepare()\n",
            "prepared.url = url\n",
            "prepared.headers = headers\n",
            "prepared.body = body\n\n",
            "with requests.Session() as session:\n",
            "    response = session.send(prepared, allow_redirects=False, timeout=30)\n",
            "    print(response.status_code)\n",
            "    print(response.text)\n",
        ),
        python_string(request.method()),
    )?;
    Ok(script)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Destination;

    fn flow(body: &[u8]) -> Exchange {
        Exchange {
            id: 1,
            timestamp_ms: 0,
            tool: "Proxy".into(),
            destination: Destination::from_url("https://example.test").unwrap(),
            url: "https://example.test/a/../b?q=';$(echo injected)&x=1".into(),
            method: "POST".into(),
            request: [
                b"POST / HTTP/2\r\nHost: virtual.test\r\nX-Repeat: first\r\nX-Repeat: second\r\nX-Empty: \r\nCookie: id='secret'\r\nContent-Length: 999\r\n\r\n".as_slice(),
                body,
            ].concat(),
            response: vec![],
            status: 0,
            duration_ms: 0,
            error: None,
            note: String::new(),
        }
    }

    #[test]
    fn curl_preserves_headers_and_quotes_shell_metacharacters() {
        let command = curl(&flow(b"hello 'world'")).unwrap();
        assert!(command.contains("--request 'POST'"));
        assert!(command.contains("--http2"));
        assert!(!command.lines().any(|line| line.starts_with('+')));
        assert!(
            command.contains("--url 'https://example.test/a/../b?q='\"'\"';$(echo injected)&x=1'")
        );
        assert!(command.contains("--header 'Host: virtual.test'"));
        assert!(command.contains("--header 'X-Repeat: first'"));
        assert!(command.contains("--header 'X-Repeat: second'"));
        assert!(command.contains("--header 'X-Empty;'"));
        assert!(command.contains("--header 'Content-Length: 13'"));
        assert!(command.contains("--data-binary 'hello '\"'\"'world'\"'\"''"));
    }

    #[test]
    fn binary_and_at_prefixed_bodies_use_stdin_instead_of_shell_arguments_or_files() {
        for body in [b"\0\xff\r\n".as_slice(), b"@/private/file"] {
            let command = curl(&flow(body)).unwrap();
            assert!(command.starts_with("printf '%b' '"));
            assert!(command.ends_with("--data-binary @-"));
            assert!(!command.contains('\0'));
        }
        assert!(
            curl(&flow(b"\0\xff\r\n"))
                .unwrap()
                .contains("\\0000\\0377\\0015\\0012")
        );
    }

    #[test]
    fn python_preserves_binary_body_duplicate_headers_and_updates_length() {
        let script = python(&flow(b"\0\xff'\\\r\n")).unwrap();
        assert!(script.contains("body = b'\\x00\\xff\\'\\\\\\r\\n'"));
        assert!(script.contains("headers.add(\"X-Repeat\", \"first\")"));
        assert!(script.contains("headers.add(\"X-Repeat\", \"second\")"));
        assert!(script.contains("headers.add(\"Content-Length\", \"6\")"));
        assert!(script.contains("allow_redirects=False"));
        assert!(script.contains("\n    response = session.send("));
    }

    #[test]
    fn invalid_requests_fail_instead_of_copying_partial_commands() {
        let mut flow = flow(b"");
        flow.request = b"invalid".to_vec();
        assert!(curl(&flow).is_err());
        assert!(python(&flow).is_err());
    }
}
