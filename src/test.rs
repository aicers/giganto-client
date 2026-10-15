//! Shared test code

use std::{
    future::{Future, IntoFuture},
    time::Duration,
};

use quinn::{Connection, RecvStream, SendStream};

pub(crate) struct Channel {
    pub(crate) server: Endpoint,
    pub(crate) client: Endpoint,
}

pub(crate) struct Endpoint {
    pub(crate) conn: Connection,
    pub(crate) send: SendStream,
    pub(crate) recv: RecvStream,
}

pub(crate) const WAIT_TIMEOUT: Duration = Duration::from_secs(10);
pub(crate) const EVENT_WAIT_TIMEOUT: Duration = Duration::from_secs(5);

/// Bounds one asynchronous operation, keeping timeout failures separate from its result.
pub(crate) async fn wait<F: Future>(operation: &str, future: F) -> F::Output {
    wait_with_timeout(operation, WAIT_TIMEOUT, future).await
}

/// Bounds propagation of a stream-stop or connection-close event.
pub(crate) async fn wait_for_event<F: Future>(operation: &str, future: F) -> F::Output {
    wait_with_timeout(operation, EVENT_WAIT_TIMEOUT, future).await
}

async fn wait_with_timeout<F: Future>(operation: &str, duration: Duration, future: F) -> F::Output {
    tokio::time::timeout(duration, future)
        .await
        .unwrap_or_else(|_| panic!("timed out after {duration:?} waiting for {operation}"))
}

/// Creates a bidirectional channel, returning server's send and receive and
/// client's send and receive streams.
pub(crate) async fn channel() -> Channel {
    use std::{
        net::{IpAddr, Ipv6Addr, SocketAddr},
        sync::Arc,
    };

    use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
    const TEST_SERVER_NAME: &str = "test-server";

    let cert =
        rcgen::generate_simple_self_signed([TEST_SERVER_NAME.to_string()]).expect("infallible");
    let cert_der = vec![CertificateDer::from(cert.cert)];
    let key_der = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    let server_config = quinn::ServerConfig::with_single_cert(cert_der.clone(), key_der.into())
        .expect("infallible");
    let server_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0);

    let server_endpoint = quinn::Endpoint::server(server_config, server_addr)
        .unwrap_or_else(|err| panic!("failed to create test server at {server_addr}: {err}"));
    let server_addr = server_endpoint
        .local_addr()
        .expect("test server local address");

    let handle = tokio::spawn(async move {
        let server_connection = match wait(
            "test server accepting incoming connection",
            server_endpoint.accept(),
        )
        .await
        {
            Some(conn) => {
                match wait("test server establishing connection", conn.into_future()).await {
                    Ok(conn) => conn,
                    Err(e) => panic!("{}", e.to_string()),
                }
            }
            None => panic!("connection closed"),
        };
        let (server_send, mut server_recv) = wait(
            "test server accepting bidirectional stream",
            server_connection.accept_bi(),
        )
        .await
        .unwrap();
        let mut server_buf = [0; 5];
        wait(
            "test server receiving ready message",
            server_recv.read_exact(&mut server_buf),
        )
        .await
        .unwrap();
        (server_connection, server_send, server_recv)
    });

    let mut root_cert_store = rustls::RootCertStore::empty();
    root_cert_store.add_parsable_certificates(cert_der);
    let client_config = quinn::ClientConfig::with_root_certificates(Arc::new(root_cert_store))
        .expect("invalid client config");
    let client_endpoint =
        quinn::Endpoint::client(SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)).unwrap();
    let client_connecting = client_endpoint
        .connect_with(client_config, server_addr, TEST_SERVER_NAME)
        .unwrap();

    let client_connection = wait("test client establishing connection", client_connecting)
        .await
        .unwrap();
    let (mut client_send, client_recv) = wait(
        "test client opening bidirectional stream",
        client_connection.open_bi(),
    )
    .await
    .unwrap();
    wait(
        "test client sending ready message",
        client_send.write_all(b"ready"),
    )
    .await
    .unwrap();

    let (server_connection, server_send, server_recv) =
        wait("test server setup task", handle).await.unwrap();

    Channel {
        server: self::Endpoint {
            conn: server_connection,
            send: server_send,
            recv: server_recv,
        },
        client: self::Endpoint {
            conn: client_connection,
            send: client_send,
            recv: client_recv,
        },
    }
}

/// Asserts that a serialized range-data datetime field is in the canonical
/// RFC 3339 contract format and decodes back to `expected_ns`.
///
/// The field is parsed independently of `convert_time_format` (via `jiff`), so
/// this pins the actual wire format instead of echoing the producer: a
/// regression to the old epoch-decimal text would fail to parse here.
pub(crate) fn assert_canonical_time(field: &str, expected_ns: i64) {
    assert!(
        field.ends_with("+00:00"),
        "expected numeric +00:00 offset, got {field}"
    );
    assert!(
        !field.ends_with('Z'),
        "expected +00:00 offset, not Z: {field}"
    );

    let parsed: jiff::Timestamp = field
        .parse()
        .unwrap_or_else(|err| panic!("field is not RFC 3339: {field}: {err}"));
    assert_eq!(
        i64::try_from(parsed.as_nanosecond()).unwrap(),
        expected_ns,
        "decoded timestamp mismatch for {field}"
    );
}
