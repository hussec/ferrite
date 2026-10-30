//! HTTP/2 framing with the same bounded, decoded message model used by the editors.
use crate::{
    http::Message,
    model::{Destination, Settings},
    transport::Stream,
};
use anyhow::{Context, Result, ensure};
use bytes::Bytes;
use http::{HeaderMap, Request, Response, Version};

fn headers(map: &HeaderMap) -> Result<Vec<(String, String)>> {
    map.iter()
        .map(|(name, value)| Ok((name.as_str().into(), value.to_str()?.into())))
        .collect()
}

pub async fn receive_body(mut stream: h2::RecvStream, budget: usize) -> Result<Vec<u8>> {
    let mut body = Vec::new();
    while let Some(chunk) = stream.data().await {
        let chunk = chunk?;
        ensure!(
            chunk.len() <= budget.saturating_sub(body.len()),
            "HTTP/2 body exceeds message limit"
        );
        body.extend_from_slice(&chunk);
        stream.flow_control().release_capacity(chunk.len())?;
    }
    if let Some(trailers) = stream.trailers().await? {
        let size: usize = trailers
            .iter()
            .map(|(k, v)| k.as_str().len() + v.len() + 4)
            .sum();
        ensure!(
            size <= budget.saturating_sub(body.len()),
            "HTTP/2 trailers exceed message limit"
        );
    }
    Ok(body)
}

pub async fn send_body(mut stream: h2::SendStream<Bytes>, body: &[u8]) -> Result<()> {
    let mut offset = 0;
    while offset < body.len() {
        stream.reserve_capacity((body.len() - offset).min(16 * 1024));
        let capacity = std::future::poll_fn(|cx| stream.poll_capacity(cx))
            .await
            .context("HTTP/2 stream closed before body was sent")??;
        let count = capacity.min(body.len() - offset).min(16 * 1024);
        if count == 0 {
            continue;
        }
        stream.send_data(
            Bytes::copy_from_slice(&body[offset..offset + count]),
            offset + count == body.len(),
        )?;
        offset += count;
    }
    Ok(())
}

pub fn request_head(message: &Message, dest: &Destination) -> Result<Request<()>> {
    let mut clean = message.clone();
    clean.remove_hop_headers();
    clean.remove("Transfer-Encoding");
    clean.remove("Trailer");
    let authority = clean
        .header("Host")
        .map(str::to_owned)
        .unwrap_or_else(|| dest.authority());
    let uri = http::Uri::builder()
        .scheme(if dest.tls { "https" } else { "http" })
        .authority(authority)
        .path_and_query(message.target())
        .build()?;
    let mut builder = Request::builder()
        .method(message.method())
        .version(Version::HTTP_2)
        .uri(uri);
    for (name, value) in &clean.headers {
        if !name.eq_ignore_ascii_case("host") {
            builder = builder.header(name, value);
        }
    }
    Ok(builder.body(())?)
}

pub fn response_head(message: &Message) -> Result<Response<()>> {
    let mut clean = message.clone();
    clean.remove_hop_headers();
    clean.remove("Transfer-Encoding");
    clean.remove("Trailer");
    let mut builder = Response::builder()
        .status(message.status())
        .version(Version::HTTP_2);
    for (name, value) in &clean.headers {
        builder = builder.header(name, value);
    }
    Ok(builder.body(())?)
}

pub async fn receive_request(request: Request<h2::RecvStream>, limit: usize) -> Result<Message> {
    let (parts, body) = request.into_parts();
    ensure!(
        parts.method != http::Method::CONNECT,
        "HTTP/2 CONNECT tunnels are not supported"
    );
    let path = parts.uri.path_and_query().map_or("/", |p| p.as_str());
    let mut message = Message {
        start: format!("{} {path} HTTP/2", parts.method),
        headers: headers(&parts.headers)?,
        body: vec![],
    };
    if let Some(authority) = parts.uri.authority() {
        // :authority determines HTTP/2 routing, even if a redundant Host was supplied.
        message.set("Host", authority.as_str().into());
    }
    let head_len = message.encode().len();
    ensure!(head_len <= limit, "HTTP/2 headers exceed message limit");
    message.body = receive_body(body, limit - head_len).await?;
    message.normalize_length();
    Ok(message)
}

struct ConnectionTask(tokio::task::JoinHandle<()>);
impl Drop for ConnectionTask {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub async fn send(
    stream: Stream,
    dest: &Destination,
    request: &Message,
    settings: &Settings,
) -> Result<Message> {
    let (client, connection) = h2::client::Builder::new()
        .enable_push(false)
        .max_header_list_size(settings.max_message_bytes.min(65536) as u32)
        .handshake(stream)
        .await?;
    let _driver = ConnectionTask(tokio::spawn(async move {
        let _ = connection.await;
    }));
    let mut client = client.ready().await?;
    let (response, body) =
        client.send_request(request_head(request, dest)?, request.body.is_empty())?;
    let receive = async {
        let (parts, body) = response.await?.into_parts();
        let mut message = Message {
            start: format!("HTTP/2 {}", parts.status.as_u16()),
            headers: headers(&parts.headers)?,
            body: vec![],
        };
        let size = message.encode().len();
        ensure!(
            size <= settings.max_message_bytes,
            "HTTP/2 headers exceed message limit"
        );
        message.body = receive_body(body, settings.max_message_bytes - size).await?;
        if request.method() != "HEAD" && !matches!(message.status(), 204 | 304) {
            message.decode_content(settings.max_message_bytes)?;
        }
        Ok::<_, anyhow::Error>(message)
    };
    let (_, response) = tokio::try_join!(send_body(body, &request.body), receive)?;
    Ok(response)
}
