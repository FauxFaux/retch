use std::io;
use std::io::Read;
use std::io::Write;
use std::net::ToSocketAddrs;
use std::sync::Arc;

use failure::err_msg;
use failure::Error;
use mio::tcp::TcpStream;
use rustls::Session;
use url::Url;
use vecio::Rawv;

const CLIENT: mio::Token = mio::Token(0);

pub fn get<S: AsRef<str>>(url: S) -> Result<(), Error> {
    unimplemented!()
}

struct TlsClient {
    socket: TcpStream,
    tls_session: rustls::ClientSession,
}

impl TlsClient {
    fn new(
        sock: TcpStream,
        hostname: webpki::DNSNameRef<'_>,
        cfg: Arc<rustls::ClientConfig>,
    ) -> TlsClient {
        TlsClient {
            socket: sock,
            tls_session: rustls::ClientSession::new(&cfg, hostname),
        }
    }

    fn do_read(&mut self) -> Result<bool, Error> {
        // Read TLS data. This fails if the underlying TCP connection is broken.

        if 0 == self.tls_session.read_tls(&mut self.socket)? {
            // "clean eof".. not sure why we would get here without a close-notify
            return Ok(true);
        }

        // Reading some TLS data might have yielded new TLS messages to process.
        // Errors from this indicate TLS protocol problems and are fatal.
        self.tls_session.process_new_packets()?;

        Ok(false)
    }

    fn do_write(&mut self) {
        self.tls_session
            .writev_tls(&mut WriteVAdapter::new(&mut self.socket))
            .unwrap();
    }

    fn register(&self, poll: &mut mio::Poll) {
        poll.register(
            &self.socket,
            CLIENT,
            self.ready_interest(),
            mio::PollOpt::level() | mio::PollOpt::oneshot(),
        )
        .unwrap();
    }

    fn reregister(&self, poll: &mut mio::Poll) {
        poll.reregister(
            &self.socket,
            CLIENT,
            self.ready_interest(),
            mio::PollOpt::level() | mio::PollOpt::oneshot(),
        )
        .unwrap();
    }

    // Use wants_read/wants_write to register for different mio-level IO readiness events.
    fn ready_interest(&self) -> mio::Ready {
        let rd = self.tls_session.wants_read();
        let wr = self.tls_session.wants_write();

        if rd && wr {
            mio::Ready::readable() | mio::Ready::writable()
        } else if wr {
            mio::Ready::writable()
        } else {
            mio::Ready::readable()
        }
    }
}

impl io::Write for TlsClient {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.tls_session.write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.tls_session.flush()
    }
}

impl io::Read for TlsClient {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.tls_session.read(bytes)
    }
}

pub fn single(url: &Url) -> Result<(), Error> {
    let host = url.host_str().ok_or_else(|| err_msg("relative url"))?;

    let port = url
        .port_or_known_default()
        .ok_or_else(|| err_msg("no port or unsupported protocol"))?;

    let addr = (host, port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| err_msg("resolution empty"))?;

    let sock = TcpStream::connect(&addr)?;

    let mut config = rustls::ClientConfig::new();
    config
        .root_store
        .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
    config.ct_logs = Some(&ct_logs::LOGS);

    let config = Arc::new(config);
    let dns_name =
        webpki::DNSNameRef::try_from_ascii_str(host).map_err(|()| err_msg("invalid sni name"))?;
    let mut tlsclient = TlsClient::new(sock, dns_name, config);

    let httpreq = format!(
        "GET / HTTP/1.1\r\nHost: {}\r\nConnection: \
         close\r\nAccept-Encoding: identity\r\n\r\n",
        host
    );
    tlsclient.write_all(httpreq.as_bytes()).unwrap();

    let mut poll = mio::Poll::new()?;
    let mut events = mio::Events::with_capacity(8);
    tlsclient.register(&mut poll);

    'polling: loop {
        poll.poll(&mut events, None)?;

        for ev in events.iter() {
            if ev.readiness().is_readable() {
                if tlsclient.do_read()? {
                    break 'polling;
                }

                let mut plaintext = Vec::new();
                let rc = tlsclient.tls_session.read_to_end(&mut plaintext);
                if !plaintext.is_empty() {
                    io::stdout().write_all(&plaintext).unwrap();
                }

                // If that fails, the peer might have started a clean TLS-level session closure.
                if let Err(err) = rc {
                    if io::ErrorKind::ConnectionAborted == err.kind() {
                        break 'polling;
                    }

                    Err(err)?;
                }
            }

            if ev.readiness().is_writable() {
                tlsclient.do_write();
            }

            tlsclient.reregister(&mut poll);
        }
    }

    drop(poll);

    Ok(())
}

pub struct WriteVAdapter<'a> {
    rawv: &'a mut dyn Rawv,
}

impl<'a> WriteVAdapter<'a> {
    pub fn new(rawv: &'a mut dyn Rawv) -> WriteVAdapter<'a> {
        WriteVAdapter { rawv }
    }
}

impl<'a> rustls::WriteV for WriteVAdapter<'a> {
    fn writev(&mut self, bytes: &[&[u8]]) -> io::Result<usize> {
        self.rawv.writev(bytes)
    }
}
