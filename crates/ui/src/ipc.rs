//! Cross-platform IPC transport for the LiveView server.
//!
//! - Unix: Unix domain sockets
//! - Windows: Named pipes

/// IPC endpoint address.
#[derive(Clone, Debug)]
pub struct IpcAddr {
    #[cfg(unix)]
    pub(crate) inner: std::path::PathBuf,
    #[cfg(windows)]
    pub(crate) inner: String,
}

impl std::fmt::Display for IpcAddr {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        #[cfg(unix)]
        return write!(f, "unix://{}", self.inner.display());
        #[cfg(windows)]
        return write!(f, "pipe://{}", self.inner);
    }
}

impl IpcAddr {
    /// Generate a PID-based address for standalone mode.
    pub fn for_agent(pid: u32) -> Self {
        #[cfg(unix)]
        return Self {
            inner: std::path::PathBuf::from(format!("/tmp/pentest-agent-{}.sock", pid)),
        };
        #[cfg(windows)]
        return Self {
            inner: format!(r"\\.\pipe\pentest-agent-{}", pid),
        };
    }

    /// Create from a Unix socket path.
    #[cfg(unix)]
    pub fn from_path(path: std::path::PathBuf) -> Self {
        Self { inner: path }
    }

    /// Create from a string (StrikeHub IPC mode on Windows — named pipe path).
    #[cfg(windows)]
    pub fn from_string(s: String) -> Self {
        Self { inner: s }
    }

    /// Remove the socket file (Unix) or no-op (Windows named pipes auto-cleanup).
    pub fn cleanup(&self) {
        #[cfg(unix)]
        {
            let _ = std::fs::remove_file(&self.inner);
        }
    }
}

// ---------------------------------------------------------------------------
// Liveview-only: IPC listener (axum Listener impl) + client stream
// ---------------------------------------------------------------------------

#[cfg(feature = "liveview")]
pub struct IpcListener {
    #[cfg(unix)]
    inner: tokio::net::UnixListener,
    #[cfg(unix)]
    addr: IpcAddr,
    #[cfg(windows)]
    pipe_name: String,
    #[cfg(windows)]
    current: tokio::net::windows::named_pipe::NamedPipeServer,
}

#[cfg(feature = "liveview")]
impl IpcListener {
    pub fn bind(addr: &IpcAddr) -> std::io::Result<Self> {
        #[cfg(unix)]
        {
            if addr.inner.exists() {
                let _ = std::fs::remove_file(&addr.inner);
            }
            let inner = tokio::net::UnixListener::bind(&addr.inner)?;
            Ok(Self {
                inner,
                addr: addr.clone(),
            })
        }
        #[cfg(windows)]
        {
            use tokio::net::windows::named_pipe::ServerOptions;
            let current = ServerOptions::new()
                .first_pipe_instance(true)
                .create(&addr.inner)?;
            Ok(Self {
                pipe_name: addr.inner.clone(),
                current,
            })
        }
    }
}

#[cfg(feature = "liveview")]
impl axum::serve::Listener for IpcListener {
    #[cfg(unix)]
    type Io = tokio::net::UnixStream;
    #[cfg(windows)]
    type Io = tokio::net::windows::named_pipe::NamedPipeServer;

    type Addr = IpcAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        #[cfg(unix)]
        loop {
            match self.inner.accept().await {
                Ok((stream, _)) => return (stream, self.addr.clone()),
                Err(e) => {
                    tracing::error!("IPC accept error: {}", e);
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }
        }
        #[cfg(windows)]
        loop {
            match self.current.connect().await {
                Ok(()) => {
                    use tokio::net::windows::named_pipe::ServerOptions;
                    let next = ServerOptions::new()
                        .create(&self.pipe_name)
                        .expect("create next named pipe instance");
                    let connected = std::mem::replace(&mut self.current, next);
                    return (
                        connected,
                        IpcAddr {
                            inner: self.pipe_name.clone(),
                        },
                    );
                }
                Err(e) => {
                    tracing::error!("Named pipe accept error: {}", e);
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        #[cfg(unix)]
        return Ok(self.addr.clone());
        #[cfg(windows)]
        return Ok(IpcAddr {
            inner: self.pipe_name.clone(),
        });
    }
}

// ---------------------------------------------------------------------------
// Client-side IPC stream
// ---------------------------------------------------------------------------

#[cfg(feature = "liveview")]
pub struct IpcStream {
    #[cfg(unix)]
    inner: tokio::net::UnixStream,
    #[cfg(windows)]
    inner: tokio::net::windows::named_pipe::NamedPipeClient,
}

#[cfg(feature = "liveview")]
impl IpcStream {
    pub async fn connect(addr: &IpcAddr) -> std::io::Result<Self> {
        #[cfg(unix)]
        {
            let inner = tokio::net::UnixStream::connect(&addr.inner).await?;
            Ok(Self { inner })
        }
        #[cfg(windows)]
        {
            use tokio::net::windows::named_pipe::ClientOptions;
            let inner = ClientOptions::new().open(&addr.inner)?;
            Ok(Self { inner })
        }
    }
}

#[cfg(feature = "liveview")]
impl tokio::io::AsyncRead for IpcStream {
    fn poll_read(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

#[cfg(feature = "liveview")]
impl tokio::io::AsyncWrite for IpcStream {
    fn poll_write(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(
        self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}
