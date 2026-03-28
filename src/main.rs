use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio::sync::Semaphore;
use tokio_rustls::{rustls, TlsAcceptor};
use rustls::{Certificate, PrivateKey, ServerConfig};
use rustls_pemfile;

use sha2::{Digest, Sha224};

// --- Configuration ---
const BACKEND_ADDR: &str = "127.0.0.1:80";
const MAX_CONNECTIONS: usize = 512;
const LISTEN_HOST: &str = "0.0.0.0";
const LISTEN_PORT: u16 = 443;
const CERT_FILE: &str = "server.crt";
const KEY_FILE: &str = "server.key";
const BUFFER_SIZE: usize = 4096;
// ---------------------


fn sha224_hex(s: &str) -> String {
    let mut hasher = Sha224::new();
    hasher.update(s.as_bytes());
    hex::encode(hasher.finalize())
}

fn parse_address(data: &[u8], cursor: &mut usize) -> Result<String, String> {
    if *cursor >= data.len() {
        return Err("Insufficient data for address type".to_string());
    }

    let atyp = data[*cursor];
    *cursor += 1;

    match atyp {
        0x01 => {
            // IPv4
            if data.len() < *cursor + 4 {
                return Err("Insufficient data for IPv4".to_string());
            }
            let ip = Ipv4Addr::new(data[*cursor], data[*cursor + 1], data[*cursor + 2], data[*cursor + 3]);
            *cursor += 4;
            Ok(ip.to_string())
        }
        0x03 => {
            // Domain
            if *cursor >= data.len() {
                return Err("Insufficient data for domain length".to_string());
            }
            let domain_len = data[*cursor] as usize;
            *cursor += 1;
            if data.len() < *cursor + domain_len {
                return Err("Insufficient data for domain".to_string());
            }
            let domain = String::from_utf8(data[*cursor..*cursor + domain_len].to_vec())
                .map_err(|e| format!("Invalid UTF-8 in domain: {}", e))?;
            *cursor += domain_len;
            Ok(domain)
        }
        0x04 => {
            // IPv6
            if data.len() < *cursor + 16 {
                return Err("Insufficient data for IPv6".to_string());
            }
            let mut ip_bytes = [0u8; 16];
            ip_bytes.copy_from_slice(&data[*cursor..*cursor + 16]);
            let ip = Ipv6Addr::from(ip_bytes);
            *cursor += 16;
            Ok(ip.to_string())
        }
        _ => Err(format!("Invalid address type: {}", atyp)),
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
        println!("WARN: Malformed UDP packet: missing CRLF after length");
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

fn encode_udp_response(addr: &str, port: u16, payload: &[u8]) -> Result<Vec<u8>, String> {
    let mut response = Vec::new();
    
    // Encode address
    if let Ok(ipv4) = addr.parse::<Ipv4Addr>() {
        response.push(0x01); // IPv4
        response.extend_from_slice(&ipv4.octets());
    } else if let Ok(ipv6) = addr.parse::<Ipv6Addr>() {
        response.push(0x04); // IPv6
        response.extend_from_slice(&ipv6.octets());
    } else {
        return Err("Invalid IP address format".to_string());
    }
    
    // Encode port and length
    response.extend_from_slice(&port.to_be_bytes());
    response.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    response.extend_from_slice(b"\r\n");
    response.extend_from_slice(payload);
    
    Ok(response)
}
use std::collections::HashSet;
use std::sync::RwLock;
async fn handle_udp_associate(
    mut client_stream: tokio_rustls::server::TlsStream<TcpStream>,
    initial_payload: Vec<u8>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let udp_socket = UdpSocket::bind("0.0.0.0:0").await?;
    println!("INFO: UDP associate endpoint created on port {}", udp_socket.local_addr()?.port());

    // Single-threaded state: No RwLocks or Channels needed anymore!
    let mut allowed_peers = HashSet::new();
    let mut tcp_buffer = initial_payload;
    let mut temp_tcp_buf = [0u8; BUFFER_SIZE];
    let mut udp_buf = [0u8; BUFFER_SIZE];

    let (mut read_half, mut write_half) = tokio::io::split(client_stream);

    // Set our 5-minute idle timeout timer
    let timeout_duration = Duration::from_secs(300);
    let sleep_future = sleep(timeout_duration);
    tokio::pin!(sleep_future); // Pin the timer so we can reset it in the loop

    loop {
        tokio::select! {
            // ========================================================
            // EVENT 1: Data arrives from the client over TCP
            // ========================================================
            tcp_result = read_half.read(&mut temp_tcp_buf) => {
                let n = match tcp_result {
                    Ok(0) => break, // Client closed TCP connection naturally
                    Ok(n) => n,
                    Err(e) => {
                        println!("ERROR: TCP read error in UDP associate: {}", e);
                        break;
                    }
                };
                
                tcp_buffer.extend_from_slice(&temp_tcp_buf[..n]);

                // Process all fully framed UDP packets in the buffer
                while !tcp_buffer.is_empty() {
                    if let Some((dest_addr, dest_port, payload, packet_size)) = parse_udp_packet(&tcp_buffer) {
                        let dest_full_addr = format!("{}:{}", dest_addr, dest_port);

                        match tokio::net::lookup_host(&dest_full_addr).await {
                            Ok(mut addrs) => {
                                if let Some(target_addr) = addrs.next() {
                                    // Trust this target IP to reply to us later
                                    allowed_peers.insert(target_addr);
                                    
                                    if let Err(e) = udp_socket.send_to(&payload, target_addr).await {
                                        println!("WARN: Failed to forward UDP to {}: {}", target_addr, e);
                                    }
                                }
                            }
                            Err(e) => println!("WARN: UDP DNS resolution failed for {}: {}", dest_full_addr, e),
                        }
                        // Remove the processed packet from the buffer
                        tcp_buffer.drain(..packet_size);
                    } else {
                        break; // Incomplete packet, wait for more TCP data
                    }
                }

                // Reset our idle timeout since we saw client activity
                sleep_future.as_mut().reset(Instant::now() + timeout_duration);
            }

            // ========================================================
            // EVENT 2: Data arrives from the target over UDP
            // ========================================================
            udp_result = udp_socket.recv_from(&mut udp_buf) => {
                match udp_result {
                    Ok((len, addr)) => {
                        // Ensure this packet is from a server the client actually requested
                        if allowed_peers.contains(&addr) {
                            let payload = &udp_buf[..len];
                            
                            match encode_udp_response(&addr.ip().to_string(), addr.port(), payload) {
                                Ok(response) => {
                                    if let Err(e) = write_half.write_all(&response).await {
                                        println!("ERROR: Failed to write UDP response to TCP client: {}", e);
                                        break; // Client disconnected unexpectedly
                                    }
                                }
                                Err(e) => println!("ERROR: Failed to encode UDP response: {}", e),
                            }
                        } else {
                            println!("WARN: Dropped unexpected UDP packet from {}", addr);
                        }
                    }
                    Err(e) => {
                        println!("ERROR: UDP socket read error: {}", e);
                        break;
                    }
                }

                // Reset our idle timeout since we saw target activity
                sleep_future.as_mut().reset(Instant::now() + timeout_duration);
            }

            // ========================================================
            // EVENT 3: The 5-minute idle timer expires
            // ========================================================
            () = &mut sleep_future => {
                println!("INFO: UDP session timed out after 5 minutes of inactivity.");
                break;
            }
        }
    }

    println!("INFO: Closing UDP tunnel cleanly.");
    Ok(())
}
use tokio::time::{sleep, Instant};

fn is_private_address(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ipv4) => {
            ipv4.is_loopback()           // 127.0.0.0/8
            || ipv4.is_private()         // 10/8, 172.16/12, 192.168/16
            || ipv4.is_link_local()      // 169.254.0.0/16
            || ipv4.is_broadcast()       // 255.255.255.255
            || ipv4.is_documentation()   // 192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24
            || ipv4.is_unspecified()     // 0.0.0.0
        }
        IpAddr::V6(ipv6) => {
            ipv6.is_loopback()           // ::1
            || ipv6.is_unspecified()     // ::
            // ULA: fc00::/7
            || (ipv6.segments()[0] & 0xfe00) == 0xfc00
            // Link-local: fe80::/10
            || (ipv6.segments()[0] & 0xffc0) == 0xfe80
        }
    }
}

async fn handle_tcp_connect(
    client_stream: tokio_rustls::server::TlsStream<TcpStream>,
    addr: String,
    port: u16,
    initial_data: Vec<u8>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    // Block reserved/privileged ports
    if port == 0 {
        println!("WARN: SSRF block: rejecting request to port 0");
        return Err("Blocked port".into());
    }

    let target_addr = format!("{}:{}", addr, port);

    // Resolve the hostname before connecting so we can inspect the IP
    let mut resolved = match timeout(
        Duration::from_secs(5),
        tokio::net::lookup_host(&target_addr)
    ).await {
        Ok(Ok(addrs)) => addrs,
        Ok(Err(e)) => {
            println!("WARN: DNS resolution failed for {}: {}", target_addr, e);
            return Err(Box::new(e));
        }
        Err(_) => {
            println!("WARN: DNS resolution timed out for {}", target_addr);
            return Err("DNS timeout".into());
        }
    };

    let target_socket_addr = match resolved.next() {
        Some(addr) => addr,
        None => {
            println!("WARN: DNS returned no addresses for {}", target_addr);
            return Err("No addresses resolved".into());
        }
    };

    // SSRF check: block private/loopback/link-local addresses
    if is_private_address(target_socket_addr.ip()) {
        println!(
            "WARN: SSRF block: {} resolved to private address {} - rejecting",
            addr, target_socket_addr.ip()
        );
        return Err("Blocked private address".into());
    }

    // Now connect using the already-resolved SocketAddr, not the hostname,
    // to prevent DNS rebinding between resolution and connect
    let mut target_stream = match timeout(
        Duration::from_secs(10),
        TcpStream::connect(target_socket_addr)
    ).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            println!("ERROR: Failed to connect to {}: {}", target_socket_addr, e);
            return Err(Box::new(e));
        }
        Err(_) => {
            println!("WARN: Connection to {} timed out", target_socket_addr);
            return Err("TCP connect timeout".into());
        }
    };

    if !initial_data.is_empty() {
        target_stream.write_all(&initial_data).await?;
    }

    let (client_read, client_write) = tokio::io::split(client_stream);
    let (target_read, target_write) = tokio::io::split(target_stream);

    tokio::select! {
        result1 = pipe_data(client_read, target_write) => {
            if let Err(e) = result1 {
                println!("ERROR: Client to target pipe error: {}", e);
            }
        }
        result2 = pipe_data(target_read, client_write) => {
            if let Err(e) = result2 {
                println!("ERROR: Target to client pipe error: {}", e);
            }
        }
    }

    Ok(())
}
use chrono::Utc;
async fn fallback_proxy(
    client_stream: tokio_rustls::server::TlsStream<TcpStream>,
    initial_data: Vec<u8>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let mut backend = match timeout(
        Duration::from_secs(5),
        TcpStream::connect(BACKEND_ADDR)
    ).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            println!("ERROR: Failed to connect to backend {}: {}", BACKEND_ADDR, e);
            return Err(Box::new(e));
        }
        Err(_) => {
            println!("ERROR: Backend connection timed out");
            return Err("Backend timeout".into());
        }
    };

    // Replay any bytes we already read from the client
    if !initial_data.is_empty() {
        backend.write_all(&initial_data).await?;
    }

    let (client_read, client_write) = tokio::io::split(client_stream);
    let (backend_read, backend_write) = tokio::io::split(backend);

    tokio::select! {
        result1 = pipe_data(client_read, backend_write) => {
            if let Err(e) = result1 { println!("ERROR: Client to backend pipe error: {}", e); }
        }
        result2 = pipe_data(backend_read, client_write) => {
            if let Err(e) = result2 { println!("ERROR: Backend to client pipe error: {}", e); }
        }
    }

    Ok(())
}
async fn pipe_data<R, W>(mut reader: R, mut writer: W) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
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
                return Err(Box::new(e));
            }
        }
    }
    Ok(())
}
use tokio::time::timeout;
use std::sync::OnceLock;
static PASSWORD_HASH: OnceLock<String> = OnceLock::new();

fn init_password_hash(password: &str) {
    PASSWORD_HASH.get_or_init(|| sha224_hex(password));
}

fn get_password_hash() -> &'static str {
    PASSWORD_HASH.get().expect("Password hash not initialized")
}// ---------------------------------------------------------

async fn handle_client(
    stream: TcpStream, 
    tls_acceptor: TlsAcceptor
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client_addr = stream.peer_addr()?;
    //println!("INFO: New connection from {}", client_addr);
    
    // --- SEC FIX: TLS Handshake Timeout (Slowloris Protection) ---
    // Unauthenticated clients can no longer hold open connections indefinitely 
    // simply by withholding the TLS ClientHello packet.
    let mut tls_stream = match timeout(Duration::from_secs(10), tls_acceptor.accept(stream)).await {
        Ok(Ok(stream)) => stream,
        Ok(Err(e)) => {
            println!("ERROR: TLS handshake failed for {}: {}", client_addr, e);
            return Err(Box::new(e));
        }
        Err(_) => {
            println!("WARN: TLS handshake timed out for {}", client_addr);
            return Err("TLS handshake timeout".into());
        }
    };
    // -------------------------------------------------------------
    
    let mut initial_buf = Vec::new();
    let mut temp_buf = [0u8; BUFFER_SIZE];
    
    // Nginx default client_header_timeout is typically 60 seconds.
    let read_result = timeout(Duration::from_secs(60), async {
        loop {
            let n = tls_stream.read(&mut temp_buf).await?;
            if n == 0 {
                break; // EOF (Client closed connection)
            }
            initial_buf.extend_from_slice(&temp_buf[..n]);
            
            // Condition 1: We have enough data to evaluate a Trojan handshake
            if initial_buf.len() >= 58 {
                break;
            }
            
            // Condition 2: Early HTTP Probe Detection
            if initial_buf.windows(4).any(|window| window == b"\r\n\r\n") {
                break;
            }
        }
        Ok::<_, std::io::Error>(())
    }).await;

    // Handle timeout, connection errors, or explicitly invalid Trojan lengths/HTTP requests
    if read_result.is_err() || initial_buf.len() < 58 {
        println!("INFO: Routing suspicious probe or HTTP request to fallback.");
        return fallback_proxy(tls_stream, initial_buf).await; 
    }
    
    let data = &initial_buf;
    
    // --- SEC FIX: Use the globally cached hash ---
    let expected_hash = get_password_hash();
    // ---------------------------------------------

    let received_hash = match std::str::from_utf8(&data[..56]) {
        Ok(hash) => hash,
        Err(_) => {
            println!("INFO: Invalid hash encoding. Routing to fallback.");
            return fallback_proxy(tls_stream, initial_buf).await; 
        }
    };
    fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    // Length mismatch is fine to leak here: both sides are always 56 bytes
    if a.len() != b.len() {
        return false;
    }
    let mut result: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        result |= x ^ y;
    }
    result == 0
}
    if !constant_time_eq(received_hash.as_bytes(), expected_hash.as_bytes()) || &data[56..58] != b"\r\n" {
        println!("INFO: Invalid password or framing. Routing to fallback.");
        return fallback_proxy(tls_stream, initial_buf).await; 
    }
    
    // ==========================================
    // AUTHENTICATION SUCCESSFUL
    // ==========================================
    
    let request_data = &data[58..];
    if request_data.is_empty() {
        println!("INFO: Authenticated but missing payload. Proxying to fallback with EMPTY buffer to prevent password leak.");
        return fallback_proxy(tls_stream, Vec::new()).await;
    }
    
    let cmd = request_data[0];
    let mut cursor = 1;
    
    // Parse target address
    let addr = match parse_address(request_data, &mut cursor) {
        Ok(addr) => addr,
        Err(e) => {
            println!("WARN: Invalid address in request: {}. Routing to fallback without password.", e);
            return fallback_proxy(tls_stream, request_data.to_vec()).await; 
        }
    };
    
    // Parse port
    if request_data.len() < cursor + 2 {
        println!("WARN: Insufficient data for port. Routing to fallback without password.");
        return fallback_proxy(tls_stream, request_data.to_vec()).await;
    }
    
    let port = u16::from_be_bytes([request_data[cursor], request_data[cursor + 1]]);
    cursor += 2;
    
    // Check CRLF before the payload
    if request_data.len() < cursor + 2 || &request_data[cursor..cursor + 2] != b"\r\n" {
        println!("WARN: Malformed request: missing CRLF. Routing to fallback without password.");
        return fallback_proxy(tls_stream, request_data.to_vec()).await;
    }
    cursor += 2;
    
    let payload = request_data[cursor..].to_vec();
    
    // Handle command
    match cmd {
        0x01 => {
            // TCP CONNECT
            //println!("INFO: TCP CONNECT request to {}:{}", addr, port);
            handle_tcp_connect(tls_stream, addr, port, payload).await
        }
        0x03 => {
            // UDP ASSOCIATE
            println!("INFO: UDP ASSOCIATE request received");
            handle_udp_associate(tls_stream, payload).await
        }
        _ => {
            println!("WARN: Unsupported command: {}. Routing to fallback without password.", cmd);
            fallback_proxy(tls_stream, request_data.to_vec()).await
        }
    }
}
fn load_tls_config() -> Result<ServerConfig, Box<dyn std::error::Error>> {
    // Load certificate and key files
    let cert_file = match std::fs::File::open(CERT_FILE) {
        Ok(file) => file,
        Err(e) => {
            println!("ERROR: Failed to open certificate file {}: {}", CERT_FILE, e);
            return Err(Box::new(e));
        }
    };
    
    let key_file = match std::fs::File::open(KEY_FILE) {
        Ok(file) => file,
        Err(e) => {
            println!("ERROR: Failed to open key file {}: {}", KEY_FILE, e);
            return Err(Box::new(e));
        }
    };
    
    let mut cert_reader = std::io::BufReader::new(cert_file);
    let mut key_reader = std::io::BufReader::new(key_file);
    
    // Parse certificates
    let certs = rustls_pemfile::certs(&mut cert_reader)?
        .into_iter()
        .map(Certificate)
        .collect::<Vec<_>>();
    
    if certs.is_empty() {
        let err_msg = format!("No certificates found in {}", CERT_FILE);
        println!("ERROR: {}", err_msg);
        return Err(err_msg.into());
    }
    
    // Parse private key
    let keys = rustls_pemfile::pkcs8_private_keys(&mut key_reader)?
        .into_iter()
        .map(PrivateKey)
        .collect::<Vec<_>>();
    
    if keys.is_empty() {
        let err_msg = format!("No private keys found in {}", KEY_FILE);
        println!("ERROR: {}", err_msg);
        return Err(err_msg.into());
    }
    
    // Build TLS config
    let mut config = ServerConfig::builder()
        .with_safe_defaults()
        .with_no_client_auth()
        .with_single_cert(certs, keys[0].clone())?;
        // Add this: advertise h2 and http/1.1, matching what real Nginx does
    config.alpn_protocols = vec![
        b"h2".to_vec(),
        b"http/1.1".to_vec(),
    ];
    Ok(config)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let password = std::env::args().nth(1).unwrap_or_else(|| {
        eprintln!("Usage: trojan-server <password>");
        std::process::exit(1);
    });
    init_password_hash(&password);
    // Load TLS configuration
    let tls_config = match load_tls_config() {
        Ok(config) => config,
        Err(e) => {
            println!("FATAL: {}", e);
            println!("Please generate certificate and key files, e.g., with:");
            println!("openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes");
            return Err(e);
        }
    };
    
    let tls_acceptor = TlsAcceptor::from(Arc::new(tls_config));
    
    // Start server
    let listen_addr = format!("{}:{}", LISTEN_HOST, LISTEN_PORT);
    let listener = match TcpListener::bind(&listen_addr).await {
        Ok(listener) => listener,
        Err(e) => {
            println!("ERROR: Failed to bind to {}: {}", listen_addr, e);
            return Err(Box::new(e));
        }
    };
    
    println!("INFO: Trojan Proxy with UDP support listening on {} with TLS", listen_addr);
    let semaphore = Arc::new(Semaphore::new(MAX_CONNECTIONS));
loop {
    // 1. Accept the connection FIRST
    let (stream, peer_addr) = match listener.accept().await {
        Ok(res) => res,
        Err(e) => {
            println!("ERROR: Failed to accept connection: {}", e);
            continue;
        }
    };

    let acceptor = tls_acceptor.clone();
    let sem = Arc::clone(&semaphore);
    
    tokio::spawn(async move {
        // 2. Then acquire the permit
        let _permit = match sem.try_acquire() {
            Ok(permit) => permit,
            Err(_) => {
                println!("WARN: Connection limit reached, dropping connection from {}.", peer_addr);
                return;
            }
        };
        
        // 3. Pass the stream to the handler
        if let Err(e) = handle_client(stream, acceptor).await {
            println!("ERROR: Client handling error: {}", e);
        }
    });
}
}
