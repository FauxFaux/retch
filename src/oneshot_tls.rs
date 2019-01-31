use std::fs::File;
use std::io;
use std::io::Read;
use std::io::Write;
use std::net::SocketAddr;
use std::sync::Arc;

use failure::err_msg;
use failure::Error;
use mio::tcp::TcpStream;
use rustls::Session;
use vecio::Rawv;

const CLIENT: mio::Token = mio::Token(0);

pub fn oneshot<S: AsRef<str>, W: AsRef<[u8]>>(
    addr: SocketAddr,
    host: S,
    send: W,
) -> Result<File, Error> {
    let sock = TcpStream::connect(&addr)?;

    let mut config = rustls::ClientConfig::new();
    config
        .root_store
        .add_server_trust_anchors(&webpki_roots::TLS_SERVER_ROOTS);
    config.ct_logs = Some(&ct_logs::LOGS);

    let config = Arc::new(config);
    let dns_name = webpki::DNSNameRef::try_from_ascii_str(host.as_ref())
        .map_err(|()| err_msg("invalid sni name"))?;
    let mut tlsclient = TlsClient::new(sock, dns_name, config);

    tlsclient.write_all(send.as_ref()).unwrap();

    let mut poll = mio::Poll::new()?;
    let mut events = mio::Events::with_capacity(8);
    tlsclient.register(&mut poll);

    let mut out = tempfile::tempfile()?;

    'polling: loop {
        poll.poll(&mut events, None)?;

        for ev in events.iter() {
            if ev.readiness().is_readable() {
                if tlsclient.maybe_read_packets()? {
                    return Ok(out);
                }

                // If that fails, the peer might have started a clean TLS-level session closure.
                match io::copy(&mut tlsclient.tls_session, &mut out) {
                    Ok(_) => (),
                    Err(ref err) if io::ErrorKind::ConnectionAborted == err.kind() => {
                        return Ok(out);
                    }
                    Err(err) => Err(err)?,
                }
            }

            if ev.readiness().is_writable() {
                tlsclient.maybe_write_packets();
            }

            tlsclient.reregister(&mut poll);
        }
    }
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

    fn maybe_read_packets(&mut self) -> Result<bool, Error> {
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

    fn maybe_write_packets(&mut self) {
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
