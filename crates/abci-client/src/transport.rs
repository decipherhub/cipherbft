//! Transport layer for ABCI connections.
//!
//! Provides TCP and Unix domain socket transports for ABCI communication.

use std::io;
use std::path::Path;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpStream, UnixStream};

/// Transport type for ABCI connections.
pub enum Transport {
    /// TCP connection.
    Tcp(TcpStream),
    /// Unix domain socket connection.
    Unix(UnixStream),
}

impl Transport {
    /// Connect to ABCI application via TCP.
    ///
    /// # Errors
    ///
    /// Returns an error if the connection fails.
    pub async fn connect_tcp(addr: &str) -> io::Result<Self> {
        let stream = TcpStream::connect(addr).await?;
        stream.set_nodelay(true)?; // Disable Nagle's algorithm for low latency
        Ok(Transport::Tcp(stream))
    }

    /// Connect to ABCI application via Unix domain socket.
    ///
    /// # Errors
    ///
    /// Returns an error if the connection fails.
    pub async fn connect_unix<P: AsRef<Path>>(path: P) -> io::Result<Self> {
        let stream = UnixStream::connect(path).await?;
        Ok(Transport::Unix(stream))
    }
}

// Implement AsyncRead for Transport
impl AsyncRead for Transport {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<io::Result<()>> {
        match &mut *self {
            Transport::Tcp(stream) => std::pin::Pin::new(stream).poll_read(cx, buf),
            Transport::Unix(stream) => std::pin::Pin::new(stream).poll_read(cx, buf),
        }
    }
}

// Implement AsyncWrite for Transport
impl AsyncWrite for Transport {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<Result<usize, io::Error>> {
        match &mut *self {
            Transport::Tcp(stream) => std::pin::Pin::new(stream).poll_write(cx, buf),
            Transport::Unix(stream) => std::pin::Pin::new(stream).poll_write(cx, buf),
        }
    }

    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), io::Error>> {
        match &mut *self {
            Transport::Tcp(stream) => std::pin::Pin::new(stream).poll_flush(cx),
            Transport::Unix(stream) => std::pin::Pin::new(stream).poll_flush(cx),
        }
    }

    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Result<(), io::Error>> {
        match &mut *self {
            Transport::Tcp(stream) => std::pin::Pin::new(stream).poll_shutdown(cx),
            Transport::Unix(stream) => std::pin::Pin::new(stream).poll_shutdown(cx),
        }
    }
}

/// Connection configuration.
#[derive(Debug, Clone)]
pub struct ConnectionConfig {
    /// Connection address (TCP address or Unix socket path).
    pub address: String,
    /// Use Unix socket instead of TCP.
    pub use_unix: bool,
    /// Connection timeout in seconds.
    pub timeout_secs: u64,
    /// Enable automatic reconnection.
    pub auto_reconnect: bool,
    /// Maximum reconnection attempts (0 = unlimited).
    pub max_reconnect_attempts: usize,
}

impl Default for ConnectionConfig {
    fn default() -> Self {
        Self {
            address: "127.0.0.1:26658".to_string(),
            use_unix: false,
            timeout_secs: 10,
            auto_reconnect: true,
            max_reconnect_attempts: 5,
        }
    }
}

impl ConnectionConfig {
    /// Create config for TCP connection.
    pub fn tcp(address: impl Into<String>) -> Self {
        Self {
            address: address.into(),
            use_unix: false,
            ..Default::default()
        }
    }

    /// Create config for Unix socket connection.
    pub fn unix(path: impl Into<String>) -> Self {
        Self {
            address: path.into(),
            use_unix: true,
            ..Default::default()
        }
    }

    /// Set connection timeout.
    pub fn with_timeout(mut self, timeout_secs: u64) -> Self {
        self.timeout_secs = timeout_secs;
        self
    }

    /// Enable or disable auto-reconnect.
    pub fn with_auto_reconnect(mut self, enabled: bool) -> Self {
        self.auto_reconnect = enabled;
        self
    }

    /// Connect using this configuration.
    ///
    /// # Errors
    ///
    /// Returns an error if the connection fails.
    pub async fn connect(&self) -> io::Result<Transport> {
        if self.use_unix {
            Transport::connect_unix(&self.address).await
        } else {
            Transport::connect_tcp(&self.address).await
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_connection_config_tcp() {
        let config = ConnectionConfig::tcp("127.0.0.1:26658");
        assert!(!config.use_unix);
        assert_eq!(config.address, "127.0.0.1:26658");
    }

    #[test]
    fn test_connection_config_unix() {
        let config = ConnectionConfig::unix("/tmp/app.sock");
        assert!(config.use_unix);
        assert_eq!(config.address, "/tmp/app.sock");
    }

    #[test]
    fn test_connection_config_builder() {
        let config = ConnectionConfig::tcp("localhost:8080")
            .with_timeout(30)
            .with_auto_reconnect(false);

        assert_eq!(config.timeout_secs, 30);
        assert!(!config.auto_reconnect);
    }
}
