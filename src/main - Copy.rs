use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio_rustls::{rustls, TlsAcceptor};
use rustls::{Certificate, PrivateKey, ServerConfig};
use rustls_pemfile;

use sha2::{Digest, Sha224};
use log::{error, info, warn};
use anyhow::{Context, Result};

// --- Configuration ---
const PASSWORD: &str = "your_password_here";
const FALLBACK_HOST: &str = "127.0.0.1";
const FALLBACK_PORT: u16 = 80;
const LISTEN_HOST: &str = "0.0.0.0";
const LISTEN_PORT: u16 = 443;
const CERT_FILE: &str = "server.crt";
const KEY_FILE: &str = "server.key";
const BUFFER_SIZE: usize = 4096;
// ---------------------

#[derive(Debug)]
enum TrojanCommand {
    Connect = 0x01,
    UdpAssociate = 0x03,
}

#[derive(Debug)]
enum AddressType {
    IPv4 = 0x01,
    Domain = 0x03,
    IPv6 = 0x04,
}

#[derive(Debug, Clone)]
struct UdpPacket {
    addr: String,
    port: u16,
    payload: Vec<u8>,
}

struct UdpSession {
    socket: Arc<UdpSocket>,
    client_tx: mpsc::UnboundedSender<Vec<u8>>,
}

fn sha224_hex(s: &str) -> String {
    let mut hasher = Sha224::new();
    hasher.update(s.as_bytes());
    hex::encode(hasher.finalize())
}

fn parse_address(data: &[u8], cursor: &mut usize) -> Result<String> {
    if *cursor >= data.len() {
        return Err(anyhow::anyhow!("Insufficient data for address type"));
    }

    let atyp = data[*cursor];
    *cursor += 1;

    match atyp {
        0x01 => {
            // IPv4
            if data.len() < *cursor + 4 {
                return Err(anyhow::anyhow!("Insufficient data for IPv4"));
            }
            let ip = Ipv4Addr::new(data[*cursor], data[*cursor + 1], data[*cursor + 2], data[*cursor + 3]);
            *cursor += 4;
            Ok(ip.to_string())
        }
        0x03 => {
            // Domain
            if *cursor >= data.len() {
                return Err(anyhow::anyhow!("Insufficient data for domain length"));
            }
            let domain_len = data[*cursor] as usize;
            *cursor += 1;
            if data.len() < *cursor + domain_len {
                return Err(anyhow::anyhow!("Insufficient data for domain"));
            }
            let domain = String::from_utf8(data[*cursor..*cursor + domain_len].to_vec())?;
            *cursor += domain_len;
            Ok(domain)
        }
        0x04 => {
            // IPv6
            if data.len() < *cursor + 16 {
                return Err(anyhow::anyhow!("Insufficient data for IPv6"));
            }
            let mut ip_bytes = [0u8; 16];
            ip_bytes.copy_from_slice(&data[*cursor..*cursor + 16]);
            let ip = Ipv6Addr::from(ip_bytes);
            *cursor += 16;
            Ok(ip.to_string())
        }
        _ => Err(anyhow::anyhow!("Invalid address type: {}", atyp)),
    }
}

fn parse_udp_packet(data: &[u8]) -> Option<(String, u16, Vec<u8>, usize)> {
    if data.len() < 4 {
        return None;
    }

    let mut cursor = 0;
    
    // Parse address
    let addr = match parse_address(data, &mut cursor) {
        Ok(addr) => addr,
        Err(_) => return None,
    };

    // Parse port and length
    if data.len() < cursor + 4 {
        return None;
    }
    
    let port = u16::from_be_bytes([data[cursor], data[cursor + 1]]);
    cursor += 2;
    
    let payload_len = u16::from_be_bytes([data[cursor], data[cursor + 1]]) as usize;
    cursor += 2;
    
    // Check for CRLF
    if data.len() < cursor + 2 || &data[cursor..cursor + 2] != b"\r\n" {
        warn!("Malformed UDP packet: missing CRLF after length");
        return None;
    }
    cursor += 2;
    
    // Extract payload
    let packet_end = cursor + payload_len;
    if data.len() < packet_end {
        return None;
    }
    
    let payload = data[cursor..packet_end].to_vec();
    
    // Check for optional trailing CRLF
    let mut total_packet_size = packet_end;
    if data.len() >= packet_end + 2 && &data[packet_end..packet_end + 2] == b"\r\n" {
        total_packet_size += 2;
    }
    
    Some((addr, port, payload, total_packet_size))
}

fn encode_udp_response(addr: &str, port: u16, payload: &[u8]) -> Result<Vec<u8>> {
    let mut response = Vec::new();
    
    // Encode address
    if let Ok(ipv4) = addr.parse::<Ipv4Addr>() {
        response.push(0x01); // IPv4
        response.extend_from_slice(&ipv4.octets());
    } else if let Ok(ipv6) = addr.parse::<Ipv6Addr>() {
        response.push(0x04); // IPv6
        response.extend_from_slice(&ipv6.octets());
    } else {
        return Err(anyhow::anyhow!("Invalid IP address format"));
    }
    
    // Encode port and length
    response.extend_from_slice(&port.to_be_bytes());
    response.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    response.extend_from_slice(b"\r\n");
    response.extend_from_slice(payload);
    
    Ok(response)
}

async fn handle_udp_associate(
    mut client_stream: tokio_rustls::server::TlsStream<TcpStream>,
    initial_payload: Vec<u8>,
) -> Result<()> {
    // Create UDP socket for this session
    let udp_socket = UdpSocket::bind("0.0.0.0:0").await?;
    let local_port = udp_socket.local_addr()?.port();
    let udp_socket = Arc::new(udp_socket);
    
    info!("UDP associate endpoint created on port {}", local_port);
    
    // Channel for sending responses back to client
    let (response_tx, mut response_rx) = mpsc::unbounded_channel::<Vec<u8>>();
    
    // Clone socket for the UDP receiver task
    let socket_clone = Arc::clone(&udp_socket);
    let response_tx_clone = response_tx.clone();
    
    // Task to handle incoming UDP responses
    tokio::spawn(async move {
        let mut buf = [0u8; BUFFER_SIZE];
        loop {
            match socket_clone.recv_from(&mut buf).await {
                Ok((len, addr)) => {
                    let addr_str = addr.ip().to_string();
                    let port = addr.port();
                    let payload = &buf[..len];
                    
                    info!("UDP response from {}:{}, {} bytes", addr_str, port, len);
                    
                    match encode_udp_response(&addr_str, port, payload) {
                        Ok(response) => {
                            if response_tx_clone.send(response).is_err() {
                                break; // Client disconnected
                            }
                        }
                        Err(e) => {
                            error!("Error encoding UDP response: {}", e);
                            break;
                        }
                    }
                }
                Err(e) => {
                    error!("UDP socket error: {}", e);
                    break;
                }
            }
        }
    });
    
    let mut buffer = initial_payload;
    
    // Split stream for concurrent read/write
    let (mut read_half, mut write_half) = tokio::io::split(client_stream);
    
    // Task to send UDP responses back to client
    tokio::spawn(async move {
        while let Some(response) = response_rx.recv().await {
            if write_half.write_all(&response).await.is_err() {
                break;
            }
        }
    });
    
    // Main loop to process UDP packets from client
    loop {
        // Process all complete packets in buffer
        while !buffer.is_empty() {
            if let Some((dest_addr, dest_port, payload, packet_size)) = parse_udp_packet(&buffer) {
                info!("UDP relay to {}:{}, {} bytes", dest_addr, dest_port, payload.len());
                
                // Send UDP packet to destination
                let dest_addr = format!("{}:{}", dest_addr, dest_port);
                if let Err(e) = udp_socket.send_to(&payload, &dest_addr).await {
                    error!("Failed to send UDP packet to {}: {}", dest_addr, e);
                }
                
                // Remove processed packet from buffer
                buffer.drain(..packet_size);
            } else {
                break; // Incomplete packet, need more data
            }
        }
        
        // Read more data from client
        let mut temp_buf = [0u8; BUFFER_SIZE];
        match read_half.read(&mut temp_buf).await {
            Ok(0) => break, // Client disconnected
            Ok(n) => buffer.extend_from_slice(&temp_buf[..n]),
            Err(e) => {
                error!("Error reading from client: {}", e);
                break;
            }
        }
    }
    
    info!("Closing UDP tunnel");
    Ok(())
}

async fn handle_tcp_connect(
    mut client_stream: tokio_rustls::server::TlsStream<TcpStream>,
    addr: String,
    port: u16,
    initial_data: Vec<u8>,
) -> Result<()> {
    // Connect to target server
    let target_addr = format!("{}:{}", addr, port);
    let mut target_stream = TcpStream::connect(&target_addr).await
        .with_context(|| format!("Failed to connect to {}", target_addr))?;
    
    info!("TCP tunnel established to {}", target_addr);
    
    // Send initial data if present
    if !initial_data.is_empty() {
        target_stream.write_all(&initial_data).await?;
    }
    
    // Start bidirectional relay
    let (client_read, client_write) = tokio::io::split(client_stream);
    let (target_read, target_write) = tokio::io::split(target_stream);
    
    let client_to_target = pipe_data(client_read, target_write);
    let target_to_client = pipe_data(target_read, client_write);
    
    // Wait for either direction to complete
    tokio::select! {
        result1 = client_to_target => {
            if let Err(e) = result1 {
                error!("Client to target pipe error: {}", e);
            }
        }
        result2 = target_to_client => {
            if let Err(e) = result2 {
                error!("Target to client pipe error: {}", e);
            }
        }
    }
    
    Ok(())
}

async fn fallback_proxy(
    mut client_stream: tokio_rustls::server::TlsStream<TcpStream>,
    initial_data: Vec<u8>,
) -> Result<()> {
    info!("Fallback: proxying traffic to {}:{}", FALLBACK_HOST, FALLBACK_PORT);
    
    let fallback_addr = format!("{}:{}", FALLBACK_HOST, FALLBACK_PORT);
    let mut fallback_stream = TcpStream::connect(&fallback_addr).await
        .with_context(|| format!("Failed to connect to fallback {}", fallback_addr))?;
    
    // Send initial data
    if !initial_data.is_empty() {
        fallback_stream.write_all(&initial_data).await?;
    }
    
    // Start bidirectional relay
    let (client_read, client_write) = tokio::io::split(client_stream);
    let (fallback_read, fallback_write) = tokio::io::split(fallback_stream);
    
    let client_to_fallback = pipe_data(client_read, fallback_write);
    let fallback_to_client = pipe_data(fallback_read, client_write);
    
    tokio::select! {
        result1 = client_to_fallback => {
            if let Err(e) = result1 {
                error!("Client to fallback pipe error: {}", e);
            }
        }
        result2 = fallback_to_client => {
            if let Err(e) = result2 {
                error!("Fallback to client pipe error: {}", e);
            }
        }
    }
    
    Ok(())
}

async fn pipe_data<R, W>(mut reader: R, mut writer: W) -> Result<()>
where
    R: tokio::io::AsyncRead + Unpin,
    W: tokio::io::AsyncWrite + Unpin,
{
    let mut buffer = [0u8; BUFFER_SIZE];
    loop {
        match reader.read(&mut buffer).await {
            Ok(0) => break, // EOF
            Ok(n) => {
                writer.write_all(&buffer[..n]).await?;
            }
            Err(e) => {
                // Ignore common connection errors
                if e.kind() == std::io::ErrorKind::ConnectionReset
                    || e.kind() == std::io::ErrorKind::BrokenPipe
                {
                    break;
                }
                return Err(e.into());
            }
        }
    }
    Ok(())
}

async fn handle_client(stream: TcpStream, tls_acceptor: TlsAcceptor) -> Result<()> {
    let client_addr = stream.peer_addr()?;
    info!("New connection from {}", client_addr);
    
    // Establish TLS connection
    let mut tls_stream = tls_acceptor.accept(stream).await
        .with_context(|| format!("TLS handshake failed for {}", client_addr))?;
    
    // Read initial data
    let mut initial_buf = [0u8; BUFFER_SIZE];
    let n = tls_stream.read(&mut initial_buf).await?;
    let data = &initial_buf[..n];
    
    if data.len() < 58 {
        warn!("Handshake failed: packet too short. Fallback.");
        return fallback_proxy(tls_stream, data.to_vec()).await;
    }
    
    // Authenticate
    let expected_hash = sha224_hex(PASSWORD);
    let received_hash = match std::str::from_utf8(&data[..56]) {
        Ok(hash) => hash,
        Err(_) => {
            warn!("Handshake failed: invalid hash format. Fallback.");
            return fallback_proxy(tls_stream, data.to_vec()).await;
        }
    };
    
    if received_hash != expected_hash || &data[56..58] != b"\r\n" {
        warn!("Handshake failed: invalid password. Fallback.");
        return fallback_proxy(tls_stream, data.to_vec()).await;
    }
    
    // Parse Trojan request
    let request_data = &data[58..];
    if request_data.is_empty() {
        warn!("Handshake failed: no request data. Fallback.");
        return fallback_proxy(tls_stream, data.to_vec()).await;
    }
    
    let cmd = request_data[0];
    let mut cursor = 1;
    
    // Parse target address
    let addr = match parse_address(request_data, &mut cursor) {
        Ok(addr) => addr,
        Err(e) => {
            warn!("Invalid address in request: {}. Fallback.", e);
            return fallback_proxy(tls_stream, data.to_vec()).await;
        }
    };
    
    // Parse port
    if request_data.len() < cursor + 2 {
        warn!("Insufficient data for port. Fallback.");
        return fallback_proxy(tls_stream, data.to_vec()).await;
    }
    
    let port = u16::from_be_bytes([request_data[cursor], request_data[cursor + 1]]);
    cursor += 2;
    
    // Check CRLF
    if request_data.len() < cursor + 2 || &request_data[cursor..cursor + 2] != b"\r\n" {
        warn!("Malformed request: missing CRLF. Fallback.");
        return fallback_proxy(tls_stream, data.to_vec()).await;
    }
    cursor += 2;
    
    let payload = request_data[cursor..].to_vec();
    
    // Handle command
    match cmd {
        0x01 => {
            // TCP CONNECT
            info!("TCP CONNECT request to {}:{}", addr, port);
            handle_tcp_connect(tls_stream, addr, port, payload).await
        }
        0x03 => {
            // UDP ASSOCIATE
            info!("UDP ASSOCIATE request received");
            handle_udp_associate(tls_stream, payload).await
        }
        _ => {
            warn!("Unsupported command: {}. Fallback.", cmd);
            fallback_proxy(tls_stream, data.to_vec()).await
        }
    }
}

fn load_tls_config() -> Result<ServerConfig> {
    // Load certificate and key files
    let cert_file = std::fs::File::open(CERT_FILE)
        .with_context(|| format!("Failed to open certificate file: {}", CERT_FILE))?;
    let key_file = std::fs::File::open(KEY_FILE)
        .with_context(|| format!("Failed to open key file: {}", KEY_FILE))?;
    
    let mut cert_reader = std::io::BufReader::new(cert_file);
    let mut key_reader = std::io::BufReader::new(key_file);
    
    // Parse certificates
    let certs = rustls_pemfile::certs(&mut cert_reader)?
        .into_iter()
        .map(Certificate)
        .collect::<Vec<_>>();
    
    if certs.is_empty() {
        return Err(anyhow::anyhow!("No certificates found in {}", CERT_FILE));
    }
    
    // Parse private key
    let keys = rustls_pemfile::pkcs8_private_keys(&mut key_reader)?
        .into_iter()
        .map(PrivateKey)
        .collect::<Vec<_>>();
    
    if keys.is_empty() {
        return Err(anyhow::anyhow!("No private keys found in {}", KEY_FILE));
    }
    
    // Build TLS config
    let config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, keys[0].clone())?;
    
    Ok(config)
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    
    // Load TLS configuration
    let tls_config = match load_tls_config() {
        Ok(config) => config,
        Err(e) => {
            error!("FATAL: {}", e);
            error!("Please generate certificate and key files, e.g., with:");
            error!("openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes");
            return Err(e);
        }
    };
    
    let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));
    
    // Start server
    let listen_addr = format!("{}:{}", LISTEN_HOST, LISTEN_PORT);
    let listener = TcpListener::bind(&listen_addr).await
        .with_context(|| format!("Failed to bind to {}", listen_addr))?;
    
    info!("Trojan Proxy with UDP support listening on {} with TLS", listen_addr);
    
    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                let acceptor = tls_acceptor.clone();
                tokio::spawn(async move {
                    if let Err(e) = handle_client(stream, acceptor).await {
                        error!("Client handling error: {}", e);
                    }
                });
            }
            Err(e) => {
                error!("Failed to accept connection: {}", e);
            }
        }
    }
}