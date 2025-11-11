//! Shared helpers for integration tests.

use std::{
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::{Arc, LazyLock},
};

use quinn::{Connection, RecvStream, SendStream};
use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use serde::{de::DeserializeOwned, Serialize};
use tokio::sync::Mutex;

const TEST_SERVER_NAME: &str = "test-server";
const TEST_PORT: u16 = 60190;

#[allow(dead_code)]
pub struct Channel {
    pub server: Endpoint,
    pub client: Endpoint,
}

#[allow(dead_code)]
pub struct Endpoint {
    pub conn: Connection,
    pub send: SendStream,
    pub recv: RecvStream,
}

pub static TOKEN: LazyLock<Mutex<u32>> = LazyLock::new(|| Mutex::new(0));

/// Creates a bidirectional channel between a server and client QUIC endpoint.
pub async fn channel() -> Channel {
    let cert =
        rcgen::generate_simple_self_signed([TEST_SERVER_NAME.to_string()]).expect("infallible");
    let cert_der = vec![CertificateDer::from(cert.cert)];
    let key_der = PrivatePkcs8KeyDer::from(cert.key_pair.serialize_der());
    let server_config = quinn::ServerConfig::with_single_cert(cert_der.clone(), key_der.into())
        .expect("infallible");
    let server_addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), TEST_PORT);

    let server_endpoint = loop {
        break match quinn::Endpoint::server(server_config.clone(), server_addr) {
            Ok(e) => e,
            Err(e) if e.kind() == tokio::io::ErrorKind::AddrInUse => {
                tokio::time::sleep(std::time::Duration::from_millis(1000)).await;
                continue;
            }
            Err(e) => panic!("{}", e),
        };
    };

    let handle = tokio::spawn(async move {
        let server_connection = match server_endpoint.accept().await {
            Some(conn) => match conn.await {
                Ok(conn) => conn,
                Err(e) => panic!("{e}"),
            },
            None => panic!("connection closed"),
        };
        let (server_send, mut server_recv) = server_connection.accept_bi().await.unwrap();
        let mut server_buf = [0; 5];
        server_recv.read_exact(&mut server_buf).await.unwrap();
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

    let client_connection = client_connecting.await.unwrap();
    let (mut client_send, client_recv) = client_connection.open_bi().await.unwrap();
    client_send.write_all(b"ready").await.unwrap();

    let (server_connection, server_send, server_recv) = handle.await.unwrap();

    Channel {
        server: Endpoint {
            conn: server_connection,
            send: server_send,
            recv: server_recv,
        },
        client: Endpoint {
            conn: client_connection,
            send: client_send,
            recv: client_recv,
        },
    }
}

// NOTE: If bincode version is updated, replace body of this function with the new one.
#[allow(dead_code)]
pub fn encode_legacy<T: Serialize>(data: &T) -> Result<Vec<u8>, bincode::error::EncodeError> {
    bincode::serde::encode_to_vec(data, bincode::config::legacy())
}

// NOTE: If bincode version is updated, replace body of this function with the new one.
#[allow(dead_code)]
pub fn decode_legacy<T: DeserializeOwned>(data: &[u8]) -> Result<T, bincode::error::DecodeError> {
    let (result, _len) = bincode::serde::decode_from_slice(data, bincode::config::legacy())?;
    Ok(result)
}

/// Creates a sample `Conn` for testing purposes.
///
/// This function uses `serde_json` to deserialize the `Conn` struct from JSON,
/// ensuring that the test remains unaffected even if `start_time` or `end_time`
/// change to `i64` or `jiff` (jiffies) in the future.
#[allow(dead_code)]
pub fn sample_conn() -> giganto_client::ingest::network::Conn {
    use serde_json::json;

    serde_json::from_value(json!({
        "orig_addr": "192.168.4.76",
        "orig_port": 46378,
        "resp_addr": "192.168.4.76",
        "resp_port": 80,
        "proto": 6,
        "conn_state": "",
        "start_time": "1970-01-01T00:00:00.123456789Z",
        "end_time": "1970-01-01T00:00:00.987654321Z",
        "duration": 864_197_532,
        "service": "-",
        "orig_bytes": 77,
        "resp_bytes": 295,
        "orig_pkts": 397,
        "resp_pkts": 511,
        "orig_l2_bytes": 21515,
        "resp_l2_bytes": 27889,
    }))
    .expect("valid Conn payload")
}
