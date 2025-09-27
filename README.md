# Trojan GFW Proxy Server with UDP Support

A Rust implementation of a Trojan proxy server that supports both TCP and UDP traffic over TLS, with fallback capabilities for legitimate HTTPS traffic.

## What This Is

This is a fully-featured Trojan proxy server built in Rust. It implements the Trojan protocol specification, allowing it to masquerade as legitimate HTTPS traffic while proxying both TCP and UDP connections to target destinations. The server uses TLS encryption and includes a fallback mechanism that redirects unrecognized traffic to a legitimate HTTPS site (Google by default).

## Features

- ✅ **Full Trojan Protocol Support**: Implements the complete Trojan specification with proper authentication
- ✅ **TCP & UDP Proxying**: Handles both connection types with proper packet parsing
- ✅ **TLS Encryption**: Uses rustls for secure connections
- ✅ **Fallback Mode**: Redirects invalid traffic to legitimate HTTPS sites
- ✅ **SHA-224 Authentication**: Secure password-based client authentication
- ✅ **Concurrent Connections**: Handles multiple clients simultaneously with async/await
- ✅ **UDP Packet Parsing**: Properly handles UDP packet format with address encoding
- ✅ **Logging**: Comprehensive request/response logging for debugging

## Requirements

- Rust 1.70+ 
- OpenSSL (for certificate generation)
- A domain name pointing to your server (recommended for stealth)

## Setup Instructions

### 1. Clone and Build



### 2. Generate TLS Certificates

You'll need valid TLS certificates for the server:

```bash
# Generate self-signed certificate (for testing)
openssl req -x509 -newkey rsa:4096 -keyout server.key -out server.crt -days 365 -nodes -subj "/C=US/ST=State/L=City/O=Organization/CN=your-domain.com"

# Or use a proper certificate from Let's Encrypt
```

### 3. Configure the Server

Edit the configuration constants at the top of `main.rs`:

```rust
const PASSWORD: &str = "your_secure_password_here";  // Change this!
const FALLBACK_HOST: &str = "https://google.com";    // Fallback destination
const LISTEN_PORT: u16 = 443;                       // Usually 443 for HTTPS
```

### 4. Run the Server

```bash
# Make sure certificates are in the same directory
./target/release/trojan-server
```

## How It Works

### Authentication Process
1. Client connects and sends SHA-224 hash of password (56 bytes)
2. Followed by `\r\n` delimiter (2 bytes)  
3. Then Trojan command and destination address
4. Server validates the hash against configured password
5. If invalid, traffic is redirected to fallback host

### Protocol Support
- **TCP CONNECT** (`0x01`): Establishes TCP tunnel to target
- **UDP ASSOCIATE** (`0x03`): Creates UDP relay endpoint
- **Address Types**: IPv4, IPv6, and domain names supported

### Fallback Behavior
When authentication fails, the server acts as an HTTPS proxy to the configured fallback host (Google by default), making it appear as normal web traffic to observers.

## Security Notes

- Use a strong, unique password (the longer the better)
- Consider using a proper certificate from a CA for better stealth
- Monitor logs for suspicious activity
- The fallback feature helps maintain cover by serving legitimate content

## Performance

Built with Tokio for async I/O, this server can handle hundreds of concurrent connections efficiently. The UDP implementation properly handles packet fragmentation and reassembly.

## Troubleshooting

### Common Issues
- **Certificate errors**: Ensure `server.crt` and `server.key` are in the working directory
- **Port binding**: Make sure port 443 isn't already in use
- **Authentication failures**: Verify client and server passwords match exactly

### Logging
The server outputs detailed logs showing connection attempts, authentication status, and traffic routing decisions.

## Disclaimer

This software is intended for legitimate network administration and personal use only. Please ensure compliance with local laws and regulations regarding proxy services and network traffic management.
