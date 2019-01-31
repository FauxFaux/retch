use std::fs;
use std::io;
use std::io::Read;
use std::io::Seek;
use std::io::SeekFrom;
use std::io::Write;
use std::net::ToSocketAddrs;
use std::sync::Arc;

use failure::bail;
use failure::err_msg;
use failure::Error;
use iowrap::ReadMany;
use url::Url;

mod oneshot_tls;

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub struct StatusCode(u16);

pub struct Response {
    response_code: u16,
    inner: io::BufReader<fs::File>,
    header_end: u64,
}

pub fn get(url: &Url) -> Result<Response, Error> {
    let host = url.host_str().ok_or_else(|| err_msg("relative url"))?;

    let port = url
        .port_or_known_default()
        .ok_or_else(|| err_msg("no port or unsupported protocol"))?;

    let addr = (host, port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| err_msg("resolution empty"))?;

    let httpreq = format!(
        "GET {}{} HTTP/1.1\r\nHost: {}\r\nConnection: \
         close\r\nAccept-Encoding: identity\r\n\r\n",
        url.path(),
        url.query()
            .map(|q| format!("?{}", q))
            .unwrap_or(String::new()),
        host
    );

    let mut out = oneshot_tls::oneshot(addr, host, httpreq)?;

    out.seek(SeekFrom::Start(0))?;

    let mut buf = [0u8; 32 * 1024];
    let peek = out.read_many(&mut buf)?;
    let buf = &buf[..peek];

    let (status_line, buf) = match memchr::memchr(b'\n', buf) {
        Some(end) => buf.split_at(end),
        None => bail!("status line too long"),
    };

    let status_line = String::from_utf8(status_line.to_vec())?;
    let mut status_line = status_line.split_whitespace();

    let _http_version = status_line
        .next()
        .ok_or_else(|| err_msg("invalid status line: no http version"))?;
    let response_code = status_line
        .next()
        .ok_or_else(|| err_msg("invalid status line: no response code"))?
        .parse()?;

    let mut headers = [httparse::EMPTY_HEADER; 64];

    let (header_end, headers) = match httparse::parse_headers(buf, &mut headers)? {
        httparse::Status::Complete(r) => r,
        httparse::Status::Partial => bail!("headers are too long (or horribly invalid)"),
    };

    assert!(header_end < buf.len());
    let header_end = header_end as u64;

    out.seek(SeekFrom::Start(header_end))?;

    Ok(Response {
        response_code,
        header_end,
        inner: io::BufReader::new(out),
    })
}

impl Response {
    pub fn rewind(&mut self) -> io::Result<()> {
        self.inner.seek(SeekFrom::Start(self.header_end))?;
        Ok(())
    }

    pub fn status(&self) -> StatusCode {
        StatusCode(self.response_code)
    }
}

impl StatusCode {
    pub fn is_success(&self) -> bool {
        self.0 >= 200 && self.0 <= 299
    }
}
