//! The listener. Hand-rolled over `axum::serve` for TLS and for limits on what
//! a client that has not authenticated can hold open.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::Request;
use axum::Router;
use hyper::server::conn::http1;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::service::TowerToHyperService;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::{watch, Semaphore};
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;
use tower::ServiceExt;

use crate::auth::Peer;
use crate::tls::Tls;

#[derive(Clone, Copy, Debug)]
pub struct Limits {
    pub connections: usize,
    /// For the TLS handshake, and for each request's headers.
    pub handshake: Duration,
    pub header: Duration,
    /// A connection this old finishes its request and closes; then it gets
    /// `drain`. What ends a client that reads its response one byte at a time.
    pub lifetime: Duration,
    /// How long open connections get to finish after a stop.
    pub drain: Duration,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            connections: 256,
            handshake: Duration::from_secs(10),
            header: Duration::from_secs(10),
            lifetime: Duration::from_secs(300),
            drain: Duration::from_secs(5),
        }
    }
}

/// Serves until `stop` is true, then drains. `Err` only for a listener that
/// must not be served at all.
pub async fn serve(
    listener: TcpListener,
    app: Router,
    tls: Option<&Tls>,
    limits: Limits,
    mut stop: watch::Receiver<bool>,
) -> io::Result<()> {
    let local = listener.local_addr()?;
    // Asked of the socket itself, whatever the configuration said: credentials
    // must not cross a network in the clear.
    if tls.is_none() && !local.ip().to_canonical().is_loopback() {
        return Err(io::Error::other("plain HTTP is served only on loopback"));
    }
    let acceptor = tls.map(|t| TlsAcceptor::from(t.config.clone()));
    let slots = Arc::new(Semaphore::new(limits.connections));
    let mut open = JoinSet::new();
    loop {
        let accepted = tokio::select! {
            () = stopped(&mut stop) => break,
            Some(_) = open.join_next() => continue,
            a = async {
                let slot = slots.clone().acquire_owned().await.map_err(io::Error::other)?;
                listener.accept().await.map(|(s, p)| (s, p, slot))
            } => a,
        };
        let (stream, peer, slot) = match accepted {
            Ok(a) => a,
            Err(e) => {
                // Usually out of descriptors; retrying at once would spin.
                tracing::warn!(error = %e, "accept failed");
                tokio::time::sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let (app, acceptor, mut stop) = (app.clone(), acceptor.clone(), stop.clone());
        open.spawn(async move {
            let _slot = slot;
            let Some(acceptor) = acceptor else {
                return connection(stream, peer, app, limits, stop).await;
            };
            let shake = tokio::time::timeout(limits.handshake, acceptor.accept(stream));
            tokio::select! {
                () = stopped(&mut stop) => {}
                done = shake => match done {
                    Ok(Ok(s)) => connection(s, peer, app, limits, stop).await,
                    Ok(Err(e)) => tracing::debug!(%peer, error = %e, "TLS handshake failed"),
                    Err(_) => tracing::debug!(%peer, "TLS handshake timed out"),
                }
            }
        });
    }
    drop(listener);
    let drained = tokio::time::timeout(limits.drain, async {
        while open.join_next().await.is_some() {}
    });
    if drained.await.is_err() {
        tracing::warn!(
            "connections still open after {:?}; exiting anyway",
            limits.drain
        );
    }
    Ok(())
}

async fn connection<S>(
    stream: S,
    peer: SocketAddr,
    app: Router,
    limits: Limits,
    mut stop: watch::Receiver<bool>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let service = app.map_request(move |mut req: Request<hyper::body::Incoming>| {
        req.extensions_mut().insert(Peer(peer));
        req.map(axum::body::Body::new)
    });
    let conn = http1::Builder::new()
        .timer(TokioTimer::new())
        .header_read_timeout(limits.header)
        .max_buf_size(32 * 1024)
        .serve_connection(TokioIo::new(stream), TowerToHyperService::new(service));
    let mut conn = std::pin::pin!(conn);
    let ended = tokio::select! {
        r = conn.as_mut() => Some(r),
        () = stopped(&mut stop) => None,
        _ = tokio::time::sleep(limits.lifetime) => None,
    };
    let ended = match ended {
        Some(r) => r,
        None => {
            conn.as_mut().graceful_shutdown();
            tokio::time::timeout(limits.drain, conn)
                .await
                .unwrap_or(Ok(()))
        }
    };
    if let Err(e) = ended {
        tracing::debug!(%peer, error = %e, "connection ended");
    }
}

/// Also when the sender is gone: nothing could ask for a stop any more.
async fn stopped(stop: &mut watch::Receiver<bool>) {
    let _ = stop.wait_for(|s| *s).await;
}
