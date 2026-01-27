//! Prometheus metrics HTTP server.

use crate::REGISTRY;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use prometheus::Encoder;
use std::convert::Infallible;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tracing::{error, info};

/// Handle incoming HTTP requests.
async fn handle_request(
    req: Request<hyper::body::Incoming>,
) -> Result<Response<Full<Bytes>>, Infallible> {
    match req.uri().path() {
        "/metrics" => {
            let encoder = prometheus::TextEncoder::new();
            let metric_families = REGISTRY.gather();

            let mut buffer = Vec::new();
            if let Err(e) = encoder.encode(&metric_families, &mut buffer) {
                error!("Failed to encode metrics: {}", e);
                return Ok(Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Full::new(Bytes::from("Failed to encode metrics")))
                    .unwrap());
            }

            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("Content-Type", encoder.format_type())
                .body(Full::new(Bytes::from(buffer)))
                .unwrap())
        }
        "/health" => Ok(Response::builder()
            .status(StatusCode::OK)
            .body(Full::new(Bytes::from("OK")))
            .unwrap()),
        _ => Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::new(Bytes::from("Not Found")))
            .unwrap()),
    }
}

/// Start the metrics HTTP server.
///
/// # Arguments
///
/// * `addr` - Socket address to bind to (e.g., "0.0.0.0:9100")
///
/// # Returns
///
/// A future that runs the server until cancelled.
pub async fn start_metrics_server(
    addr: SocketAddr,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let listener = TcpListener::bind(addr).await?;
    info!("Metrics server listening on http://{}/metrics", addr);

    loop {
        let (stream, _) = match listener.accept().await {
            Ok(conn) => conn,
            Err(e) => {
                error!("Failed to accept connection: {}", e);
                continue;
            }
        };
        let io = TokioIo::new(stream);

        tokio::spawn(async move {
            if let Err(e) = http1::Builder::new()
                .serve_connection(io, service_fn(handle_request))
                .await
            {
                error!("Error serving metrics connection: {}", e);
            }
        });
    }
}

/// Start the metrics server in the background.
///
/// Returns a handle that can be used to cancel the server.
pub fn spawn_metrics_server(addr: SocketAddr) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        if let Err(e) = start_metrics_server(addr).await {
            error!("Metrics server error: {}", e);
        }
    })
}
