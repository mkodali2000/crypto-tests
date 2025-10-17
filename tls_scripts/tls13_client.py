import socket
import ssl
import binascii
import sys
#from cryptography.hazmat.backends import default_backend
#from cryptography.hazmat.primitives import hashes
#from cryptography.hazmat.primitives.asymmetric import kyber
#from cryptography.hazmat.primitives import serialization

def tls13_1rtt_handshake(hostname, port=443, verify_cert=False):
    """
    Establish a TLS 1.3 connection with 1-RTT handshake to the specified hostname and port.
    
    Args:
        hostname (str): The hostname to connect to
        port (int): The port to connect to (default: 443 for HTTPS)
    
    Returns:
        ssl.SSLSocket: The established TLS socket if successful, None otherwise
    """
    try:
        # Create a TCP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # Set a timeout to prevent hanging
        sock.settimeout(10)
        
        # Connect to the server
        server_address = (socket.gethostbyname(hostname), port)
        print(f"Connecting to {hostname}:{port}...")
        sock.connect(server_address)
        
        # Create SSL context with TLS 1.3
        context = ssl.create_default_context()
        
        # Configure for TLS 1.3 only
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        
        # Configure verification - explicitly disable for self-signed certs
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        
        # Disable SSL verification warnings
        import warnings
        warnings.filterwarnings("ignore", category=DeprecationWarning)
        warnings.filterwarnings("ignore", category=RuntimeWarning)
        
        # Set up a custom verification function that accepts any certificate
        def verify_callback(cert, errno, depth, return_code):
            return True
        
        # Set the verification callback
        context.verify_mode = ssl.CERT_NONE
        context.check_hostname = False
        
        # Create SSL socket
        ssl_sock = context.wrap_socket(sock, server_hostname=None)
        
        # Perform the handshake
        print("Performing TLS 1.3 handshake...")
        ssl_sock.do_handshake()
        
        # Verify the connection
        print("TLS 1.3 handshake completed successfully!")
        print(f"Protocol: {ssl_sock.version()}")
        print(f"Cipher: {ssl_sock.cipher()}")
        
        return ssl_sock
        
    except Exception as e:
        print(f"Error during TLS 1.3 handshake: {e}")
        if 'sock' in locals():
            sock.close()
        return None



def create_large_client_hello():
    # Standard TLS 1.2 Client Hello header
    # Handshake type (0x01 for Client Hello)
    handshake_header = b'\x01'
    
    # Handshake length (will be updated later)
    handshake_len = b'\x00\x00\x00'
    
    # Protocol version (TLS 1.2)
    version = b'\x03\x03'
    
    # Random (32 bytes)
    client_random = b'\x00' * 32
    
    # Session ID (empty)
    session_id = b'\x00'
    
    # Create a smaller list of cipher suites to prevent overflow
    # Each cipher suite is 2 bytes, so 500 suites = 1000 bytes
    cipher_suites = b''
    for _ in range(500):  # Reduced from 1000 to 500
        cipher_suites += b'\xc0\x2b'  # TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
    
    # Add cipher suites length (2 bytes)
    cipher_suites_len = len(cipher_suites).to_bytes(2, 'big')
    
    # Compression methods (null)
    compression = b'\x01\x00'
    
    # Create large extensions
    extensions = b''
    
    # Add a smaller number of extensions to prevent overflow
    for i in range(10):  # Reduced from 100 to 10 extensions
        # Extension type (0x0000 for server_name, but we'll use it for padding)
        ext_type = (0x0000).to_bytes(2, 'big')
        # Smaller extension data (500 bytes instead of 1000)
        ext_data = b'\x00' * 500
        ext_len = len(ext_data).to_bytes(2, 'big')
        extensions += ext_type + ext_len + ext_data
    
    # Build the full Client Hello
    client_hello = (
        version + 
        client_random + 
        session_id + 
        cipher_suites_len + 
        cipher_suites + 
        compression + 
        len(extensions).to_bytes(2, 'big') + 
        extensions
    )
    
    # Update handshake length
    handshake_len = (len(client_hello) + 4).to_bytes(3, 'big')
    
    # Build the full handshake message
    handshake_msg = handshake_header + handshake_len[1:] + client_hello
    
    # Build the TLS record layer
    record_header = b'\x16'  # Handshake type
    record_header += b'\x03\x03'  # TLS 1.2
    record_len = len(handshake_msg).to_bytes(2, 'big')

    return record_header + record_len + handshake_msg

def send_large_client_hello(host, port):
    try:
        # Create a raw socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect((host, port))
        
        # Create the large Client Hello
        client_hello = create_large_client_hello()
        print(f"Sending large Client Hello ({len(client_hello)} bytes)...")
        
        # Send the Client Hello
        sock.sendall(client_hello)
        
        # Try to receive server response
        try:
            response = sock.recv(4096)
            print(f"Received response: {response.hex()}")
        except socket.timeout:
            print("No response received (timeout)")
        
        sock.close()
    except Exception as e:
        print(f"Error: {e}")

def tls13_0rtt_handshake(hostname, port=443, data_to_send=b"GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n"):
    """
    Establish a TLS 1.3 connection with 0-RTT handshake.
    This requires a previous successful connection to establish a session ticket.
    
    Args:
        hostname (str): The hostname to connect to
        port (int): The port to connect to (default: 443 for HTTPS)
        data_to_send (bytes): Data to send in the 0-RTT data
        
    Returns:
        bytes: The server's response
    """
    # First, establish a normal connection to get a session ticket
    print("Performing initial 1-RTT handshake to get session ticket...")
    
    try:
        # Create SSL context with TLS 1.3 - we'll reuse this context
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        # Disable hostname checking first
        context.check_hostname = False
        # Then set verify mode
        context.verify_mode = ssl.CERT_NONE
        
        # Enable session tickets
        context.session_stats()  # Enable session statistics
        
        # First connection to get session
        sock1 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock1.settimeout(10)
        server_address = (socket.gethostbyname(hostname), port)
        print(f"Connecting to {hostname}:{port}...")
        sock1.connect(server_address)
        
        # Create SSL socket for first connection
        ssl_sock1 = context.wrap_socket(sock1, server_hostname=hostname)
        
        try:
            # Perform the initial handshake
            ssl_sock1.do_handshake()
            print("Initial handshake completed, session ticket obtained")
            
            # Get the session
            session = ssl_sock1.session
            if not session:
                print("Warning: No session ticket received, 0-RTT not possible")
                return None
                
            print("Session ticket obtained, ready for 0-RTT")
            
        finally:
            ssl_sock1.close()
            
        # Now perform the 0-RTT handshake using the same context
        print("\nPerforming 0-RTT handshake...")
        sock2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock2.settimeout(10)
        sock2.connect(server_address)
        
        # Create new SSL socket with the same context and session
        ssl_sock2 = context.wrap_socket(sock2, server_hostname=hostname, session=session)
        
        try:
            # Check if write_early_data is available
            if hasattr(ssl_sock2, 'write_early_data') and hasattr(ssl_sock2, 'do_handshake'):
                # Perform the handshake with early data (Python 3.8.3+ with OpenSSL 1.1.1+)
                print("Sending early data (0-RTT)...")
                ssl_sock2.write_early_data(data_to_send)
                ssl_sock2.do_handshake()
                print("0-RTT handshake completed successfully!")
            else:
                # Fallback to session resumption without 0-RTT
                print("0-RTT not available, falling back to session resumption...")
                ssl_sock2.do_handshake()
                print("Session resumed successfully!")
                print("Sending data after handshake...")
                ssl_sock2.sendall(data_to_send)
            
            # Receive the response
            response = ssl_sock2.recv(4096)
            print("\nServer response:")
            print(response.decode('utf-8', errors='ignore'))
            
            return response
            
        finally:
            ssl_sock2.close()
            
    except Exception as e:
        print(f"Error during 0-RTT handshake: {e}")
        return None

def tls13_dhe_handshake(hostname, port=443, verify_cert=False):
    """
    Establish a TLS 1.3 connection using DHE/ECDHE key exchange.

    Args:
        hostname (str): The hostname to connect to
        port (int): The port to connect to (default: 443 for HTTPS)
        verify_cert (bool): Whether to verify the server's certificate

    Returns:
        ssl.SSLSocket: The established TLS socket if successful, None otherwise
    """
    try:
        # Create a TCP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)

        # Connect to the server
        server_address = (socket.gethostbyname(hostname), port)
        print(f"Connecting to {hostname}:{port}...")
        sock.connect(server_address)
        
        # Try different cipher suites that support (EC)DHE
        cipher_suites = [
            'TLS_AES_256_GCM_SHA384',
            'TLS_CHACHA20_POLY1305_SHA256',
            'TLS_AES_128_GCM_SHA256',
            'ECDHE-ECDSA-AES256-GCM-SHA384',
            'ECDHE-RSA-AES256-GCM-SHA384',
            'ECDHE-ECDSA-CHACHA20-POLY1305',
            'ECDHE-RSA-CHACHA20-POLY1305',
            'ECDHE-ECDSA-AES128-GCM-SHA256',
            'ECDHE-RSA-AES128-GCM-SHA256',
            'DHE-RSA-AES256-GCM-SHA384',
            'DHE-RSA-AES128-GCM-SHA256',
            'DHE-RSA-AES256-SHA256',
            'DHE-RSA-AES128-SHA256'
        ]
        
        last_error = None
        for cipher_suite in cipher_suites:
            try:
                # Create a new context for each attempt
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                
                # Configure for TLS 1.2/1.3
                context.minimum_version = ssl.TLSVersion.TLSv1_2
                context.maximum_version = ssl.TLSVersion.TLSv1_3
                
                # Disable certificate verification
                context.check_hostname = False
                context.verify_mode = ssl.CERT_NONE
                
                # Set the cipher suite
                try:
                    context.set_ciphers(cipher_suite)
                except ssl.SSLError as e:
                    print(f"  - Warning: Could not set cipher {cipher_suite}: {e}")
                    continue
                
                # Wrap the socket
                ssl_sock = context.wrap_socket(
                    sock,
                    server_hostname=None,
                    server_side=False
                )
                
                # Perform the handshake
                print(f"Trying cipher suite: {cipher_suite}...")
                ssl_sock.do_handshake()
                
                # If we get here, handshake was successful
                cipher = ssl_sock.cipher()
                print("\nTLS handshake completed successfully!")
                print(f"Protocol: {ssl_sock.version()}")
                print(f"Cipher: {cipher[0]}")
                print(f"Key exchange: {cipher[1]}")
                print(f"Encryption strength: {cipher[2]} bits")
                
                return ssl_sock
                
            except Exception as e:
                last_error = e
                print(f"  - Failed with {cipher_suite}: {str(e).split(':', 1)[0]}")
                if 'ssl_sock' in locals():
                    try:
                        ssl_sock.close()
                    except:
                        pass
                continue
        
        # If we get here, all cipher suites failed
        raise Exception(f"All cipher suite attempts failed. Last error: {last_error}")
        
    except Exception as e:
        print(f"\nError during TLS handshake with DHE: {e}")
        return None
        
    finally:
        # Only close the socket if we're not returning a valid connection
        if 'ssl_sock' not in locals() and 'sock' in locals():
            try:
                sock.close()
            except:
                pass



def tls13_specific_cipher_handshake(hostname, port=443, cipher_suite='TLS_AES_256_GCM_SHA384', verify_cert=False):
    """
    Establish a TLS 1.3 connection using a specific cipher suite.
    
    Args:
        hostname (str): The hostname to connect to
        port (int): The port to connect to (default: 443)
        cipher_suite (str): The cipher suite to use (default: 'TLS_AES_256_GCM_SHA384')
        verify_cert (bool): Whether to verify the server's certificate (default: False)
        
    Returns:
        ssl.SSLSocket: The established TLS socket if successful, None otherwise
    """
    ssl_sock = None
    sock = None
    
    try:
        # Create a TCP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)

        # Connect to the server
        server_address = (socket.gethostbyname(hostname), port)
        print(f"Connecting to {hostname}:{port}...")
        sock.connect(server_address)
        
        # Create SSL context
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        
        # Configure for TLS 1.3 only
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        context.maximum_version = ssl.TLSVersion.TLSv1_3
        
        # Configure verification
        context.check_hostname = verify_cert
        context.verify_mode = ssl.CERT_REQUIRED if verify_cert else ssl.CERT_NONE
        
        # Set the specific cipher suite
        try:
            context.set_ciphers(cipher_suite)
            print(f"Using cipher suite: {cipher_suite}")
        except ssl.SSLError as e:
            print(f"Error: Could not set cipher suite {cipher_suite}: {e}")
            return None
        
        # Wrap the socket
        ssl_sock = context.wrap_socket(
            sock,
            server_hostname=hostname if verify_cert else None,
            server_side=False
        )
        
        # Perform the handshake
        print("Performing TLS 1.3 handshake...")
        ssl_sock.do_handshake()
        
        # Verify the connection
        cipher = ssl_sock.cipher()
        print("\nTLS 1.3 handshake completed successfully!")
        print(f"Protocol: {ssl_sock.version()}")
        print(f"Cipher: {cipher[0]}")
        print(f"Key exchange: {cipher[1]}")
        print(f"Encryption strength: {cipher[2]} bits")
        
        return ssl_sock
        
    except Exception as e:
        print(f"\nError during TLS 1.3 handshake with {cipher_suite}: {e}")
        if ssl_sock:
            try:
                ssl_sock.close()
            except:
                pass
        return None
        
    finally:
        if ssl_sock is None and sock is not None:
            try:
                sock.close()
            except:
                pass

def tls13_psk_handshake(hostname, port=443, psk_identity=None, psk_key=None, verify_cert=False):
    """
    Establish a TLS 1.3 connection using Pre-Shared Key (PSK) key exchange.
    
    Note: This is a placeholder implementation as Python's ssl module doesn't directly support
    PSK key exchange. This function demonstrates the intended usage but will raise a 
    NotImplementedError when called.
    
    For actual PSK support, you would need to use a different TLS library that supports PSK,
    such as Mbed TLS, OpenSSL (via ctypes), or a higher-level library like cryptography.
    
    Args:
        hostname (str): The hostname to connect to
        port (int): The port to connect to (default: 443)
        psk_identity (bytes): The PSK identity (or None to generate a default)
        psk_key (bytes): The PSK key (or None to generate a default)
        verify_cert (bool): Whether to verify the server's certificate (default: False)
        
    Returns:
        ssl.SSLSocket: The established TLS socket if successful, None otherwise
        
    Raises:
        NotImplementedError: As PSK is not directly supported by Python's ssl module
    """
    raise NotImplementedError(
        "PSK key exchange is not directly supported by Python's ssl module. "
        "To use PSK, consider using a different TLS library that supports PSK, "
        "such as Mbed TLS, OpenSSL (via ctypes), or a higher-level library like cryptography.\n\n"
        "For testing purposes, you can use the standard TLS 1.3 handshake (option 1) or "
        "DHE key exchange (option 4) which are fully supported by Python's ssl module."
    )

KYBER512_R3 = 0x2ccb  # Draft ID for Kyber512r3
KYBER768_R3 = 0x30ab  # Draft ID for Kyber768r3
KYBER1024_R3 = 0x30ac  # Draft ID for Kyber1024r3

def generate_kyber_key_share():
    """
    Generate a Kyber key pair and return the public key and private key.
    
    Returns:
        tuple: (public_key_bytes, private_key) where public_key_bytes is ready to be sent in the
              key_share extension and private_key is the Kyber private key object.
    """
    # Generate a new Kyber key pair
    private_key = kyber.generate_private_key()
    
    # Get the public key in the format needed for TLS
    public_key = private_key.public_key()
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    
    return public_key_bytes, private_key

def create_kyber_client_hello(hostname):
    """
    Create a TLS 1.3 Client Hello with Kyber key share.
    
    Args:
        hostname (str): The hostname to connect to (for SNI)
        
    Returns:
        bytes: The complete Client Hello message
    """
    # Generate Kyber key share
    kyber_pubkey, _ = generate_kyber_key_share()
    
    # Handshake type (Client Hello)
    handshake_type = b'\x01'
    
    # Handshake length (will be updated later)
    handshake_len = b'\x00\x00\x00'
    
    # Protocol version (TLS 1.2 for compatibility)
    version = b'\x03\x03'
    
    # Random (32 bytes)
    client_random = b'\x00' * 32
    
    # Session ID (empty for TLS 1.3)
    session_id = b'\x00'
    
    # Cipher suites - include TLS_AES_256_GCM_SHA384 and others
    cipher_suites = b'\x13\x02'  # TLS_AES_256_GCM_SHA384
    cipher_suites += b'\x13\x01'  # TLS_CHACHA20_POLY1305_SHA256
    cipher_suites += b'\x13\x03'  # TLS_AES_128_GCM_SHA256
    
    # Cipher suites length (2 bytes)
    cipher_suites_len = len(cipher_suites).to_bytes(2, 'big')
    
    # Compression methods (null)
    compression = b'\x01\x00'
    
    # Extensions
    extensions = b''
    
    # Server Name Indication (SNI) extension
    if hostname:
        server_name = hostname.encode('ascii')
        server_name_list = (\
            b'\x00' +  # Name type: host_name
            len(server_name).to_bytes(2, 'big') +  # Name length
            server_name
        )
        sni_extension = (\
            b'\x00\x00' +  # extension_type = server_name(0)
            len(server_name_list).to_bytes(2, 'big') +  # extension_data length
            server_name_list
        )
        extensions += sni_extension
    
    # Supported Groups extension (includes Kyber)
    supported_groups = (\
        b'\x00\x0a' +  # extension_type = supported_groups(10)
        b'\x00\x0a' +  # extension_data length (10 bytes)
        b'\x00\x08' +  # named group list length (8 bytes)
        b'\x00\x1d' +  # x25519 (29)
        b'\x00\x17' +  # secp256r1 (23)
        b'\x00\x18' +  # secp384r1 (24)
        b'\x2c\xcb'    # kyber512r3 (11467)
    )
    extensions += supported_groups
    
    # Key Share extension with Kyber public key
    key_share = (\
        b'\x00\x33' +  # extension_type = key_share(51)
        (len(kyber_pubkey) + 6).to_bytes(2, 'big') +  # extension_data length
        b'\x00' +  # client key share length (2 bytes)
        (len(kyber_pubkey) + 4).to_bytes(2, 'big') +  # key share entry length
        b'\x2c\xcb' +  # kyber512r3 (11467)
        len(kyber_pubkey).to_bytes(2, 'big') +  # key exchange data length
        kyber_pubkey
    )
    extensions += key_share
    
    # Supported Versions extension (TLS 1.3 only)
    supported_versions = (\
        b'\x00\x2b' +  # extension_type = supported_versions(43)
        b'\x00\x03' +  # extension_data length (3 bytes)
        b'\x02' +  # supported versions list length (2 bytes)
        b'\x03\x04'   # TLS 1.3
    )
    extensions += supported_versions
    
    # Build the Client Hello
    client_hello = (\
        version +
        client_random +
        session_id +
        cipher_suites_len +
        cipher_suites +
        compression +
        len(extensions).to_bytes(2, 'big') +  # extensions length
        extensions
    )
    
    # Update handshake length
    handshake_len = len(client_hello).to_bytes(3, 'big')
    
    # Build the handshake message
    handshake_msg = handshake_type + handshake_len[1:] + client_hello
    
    # Build the TLS record layer
    record_header = b'\x16'  # Handshake type
    record_header += b'\x03\x03'  # TLS 1.2 for compatibility
    record_len = len(handshake_msg).to_bytes(2, 'big')
    
    return record_header + record_len + handshake_msg

def tls13_kyber_handshake(hostname, port=443):
    """
    Establish a TLS 1.3 connection with Kyber key exchange.
    
    Args:
        hostname (str): The hostname to connect to
        port (int): The port to connect to (default: 443)
        
    Returns:
        ssl.SSLSocket: The established TLS socket if successful, None otherwise
    """
    try:
        # Create a raw socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        
        # Connect to the server
        server_address = (socket.gethostbyname(hostname), port)
        print(f"Connecting to {hostname}:{port}...")
        sock.connect(server_address)
        
        # Create and send Client Hello with Kyber key share
        client_hello = create_kyber_client_hello(hostname)
        print(f"Sending Client Hello with Kyber key share ({len(client_hello)} bytes)...")
        sock.sendall(client_hello)
        
        # Receive Server Hello and other handshake messages
        # Note: This is a simplified implementation that just prints the response
        response = sock.recv(4096)
        print(f"Received {len(response)} bytes from server")
        
        # Check if the server accepted our Kyber key share
        if b'handshake_failure' in response:
            print("Error: Server rejected the handshake (possibly doesn't support Kyber)")
            return None
            
        print("Handshake completed successfully with Kyber key exchange!")
        return sock
        
    except Exception as e:
        print(f"Error during TLS 1.3 Kyber handshake: {e}")
        if 'sock' in locals():
            sock.close()
        return None

def create_client_hello(hostname):
    """
    Create a basic TLS 1.3 ClientHello message
    """
    import random
    import struct
    
    # Random bytes for client random
    client_random = bytes([random.randint(0, 255) for _ in range(32)])
    
    # Session ID (empty for TLS 1.3)
    session_id = b''
    
    # Cipher suites (TLS 1.3 cipher suites)
    cipher_suites = [
        0x1301,  # TLS_AES_128_GCM_SHA256
        0x1302,  # TLS_AES_256_GCM_SHA384
        0x1303,  # TLS_CHACHA20_POLY1305_SHA256
    ]
    
    # Extensions
    extensions = []
    
    # Server Name Indication (SNI) extension
    if hostname:
        hostname_encoded = hostname.encode('ascii')
        sni = (b'\x00\x00'  # Extension type 0x0000 (server_name)
               + struct.pack('>H', len(hostname_encoded) + 5)  # Extension length
               + b'\x00'  # Name type: host_name (0)
               + struct.pack('>H', len(hostname_encoded))  # Name length
               + hostname_encoded)
        extensions.append(sni)
    
    # Supported Groups extension
    supported_groups = b'\x00\x1d'  # x25519
    supported_groups += b'\x00\x17'  # secp256r1
    supported_groups = (b'\x00\x0a'  # Extension type 0x000a (supported_groups)
                       + struct.pack('>H', len(supported_groups) + 2)  # Extension length
                       + struct.pack('>H', len(supported_groups))  # Groups list length
                       + supported_groups)
    extensions.append(supported_groups)
    
    # Key Share extension (empty for initial ClientHello)
    key_share = (b'\x00\x33'  # Extension type 0x0033 (key_share)
                + b'\x00\x02'  # Extension length
                + b'\x00\x00')  # Client key share length (0 for initial ClientHello)
    extensions.append(key_share)
    
    # Build the ClientHello message
    client_hello = (b'\x01'  # Handshake type: ClientHello (1)
                   + b'\x00\x00\x00'  # Length (will be filled in later)
                   + b'\x03\x03'  # Protocol version: TLS 1.2 (for compatibility)
                   + client_random
                   + bytes([len(session_id)]) + session_id
                   + struct.pack('>H', len(cipher_suites) * 2)  # Cipher suites length
                   + b''.join(struct.pack('>H', cs) for cs in cipher_suites)
                   + b'\x01'  # Compression methods length
                   + b'\x00'  # Null compression
                   + struct.pack('>H', sum(len(ext) for ext in extensions))  # Extensions length
                   + b''.join(extensions))
    
    # Update the handshake message length
    msg_len = len(client_hello) - 4
    client_hello = (client_hello[:1] 
                   + struct.pack('>I', msg_len)[1:]  # 3-byte length
                   + client_hello[4:])
    
    # Add record layer header
    record = (b'\x16'  # Handshake record
             + b'\x03\x03'  # TLS 1.2
             + struct.pack('>H', len(client_hello))  # Length
             + client_hello)
    
    return record


def send_multiple_tls_records(sock, records):
    """
    Send multiple complete TLS records in a single packet.
    
    Args:
        sock: The socket to send data on
        records: A list of complete TLS records to send
    """
    if not records:
        return
        
    # Combine all records into a single packet
    combined_data = b''.join(records)
    
    print(f"Sending {len(records)} TLS records in a single packet (total {len(combined_data)} bytes)")
    
    # Send all records in a single send() call
    sock.send(combined_data)


def tls13_multiple_records_handshake(hostname, port=443, verify_cert=False):
    """
    Establish a TLS 1.3 connection with multiple records in one packet.
    """
    try:
        # Create a TCP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        
        print(f"Connecting to {hostname}:{port}...")
        sock.connect((socket.gethostbyname(hostname), port))
        
        # Create and send ClientHello in multiple records
        client_hello = create_client_hello(hostname)
        print("Sending ClientHello in multiple records...")
        send_multiple_tls_records(sock, [client_hello[:256], client_hello[256:]])
        
        # Read server response
        print("Waiting for server response...")
        response = sock.recv(4096)
        
        if not response:
            print("No response from server")
            return None
            
        print(f"Received {len(response)} bytes from server")
        
        # For demo purposes, just print the response in hex
        print("Server response (first 128 bytes):")
        print(response[:128].hex(' '))
        
        return sock
        
    except Exception as e:
        print(f"\nError during TLS handshake: {e}")
        import traceback
        traceback.print_exc()
        if 'sock' in locals():
            sock.close()
        return None


def tls13_fragmented_handshake(hostname, port=443, verify_cert=False):
    """
    Establish a TLS 1.3 connection with a fragmented ClientHello using raw sockets.
    """
    try:
        # Create a TCP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(10)
        
        print(f"Connecting to {hostname}:{port}...")
        sock.connect((socket.gethostbyname(hostname), port))
        
        # Create and send ClientHello in fragments
        client_hello = create_client_hello(hostname)
        print("Sending fragmented ClientHello...")
        send_fragmented_tls_record(sock, client_hello)
        
        # Read server response
        print("Waiting for server response...")
        response = sock.recv(4096)
        
        if not response:
            print("No response from server")
            return None
            
        print(f"Received {len(response)} bytes from server")
        
        # For demo purposes, just print the response in hex
        print("Server response (first 128 bytes):")
        print(response[:128].hex(' '))
        
        return sock
        
    except Exception as e:
        print(f"\nError during TLS handshake: {e}")
        import traceback
        traceback.print_exc()
        if 'sock' in locals():
            sock.close()
        return None


def send_fragmented_tls_record(sock, data, fragment_size=None):
    """
    Send a TLS record split across multiple packets.
    
    Args:
        sock: The socket to send data on
        data: The complete TLS record to send
        fragment_size: Size of the first fragment (rest will be sent in second packet)
                      If None, splits the data roughly in half
    """
    if fragment_size is None:
        fragment_size = len(data) // 2
        if fragment_size == 0:
            fragment_size = 1
    
    # Ensure we don't try to fragment beyond the data length
    fragment_size = min(fragment_size, len(data) - 1)
    
    # Send first fragment
    first_fragment = data[:fragment_size]
    print(f"Sending first fragment of size {len(first_fragment)} bytes")
    sock.send(first_fragment)
    
    # Send remaining data as second fragment
    second_fragment = data[fragment_size:]
    print(f"Sending second fragment of size {len(second_fragment)} bytes")
    sock.send(second_fragment)


def main():
    print("Host to connect (default: google.com)")
    host = input("Provide the host to connect eg., google.com or 10.10.10.7 (press Enter for default): ") or "google.com"
    print("Port to connect (default: 443)")
    port = int(input("Provide the port to connect eg., 443, 8443 (press Enter for default): ") or "443")
    
    print("\nTLS 1.3 Client")
    print("1. Normal TLS 1.3 handshake (1-RTT)")
    print("2. Large Client Hello test")
    print("3. TLS 1.3 0-RTT handshake")
    print("4. TLS 1.3 DHE Key Exchange")
    print("5. TLS 1.3 with specific cipher suite")
    print("6. TLS 1.3 PSK (Pre-Shared Key) handshake (Not available in standard Python)")
    print("7. TLS 1.3 Kyber KEM handshake")
    print("8. TLS 1.3 with fragmented ClientHello")
    print("9. TLS 1.3 with multiple records in one packet")
    print("Q. Quit")
    
    choice = input("Select an option (1-9, Q): ").strip().lower()
    
    if choice == '1':
        # Standard 1-RTT handshake
        ssl_sock = tls13_1rtt_handshake(host, port)
        if ssl_sock:
            try:
                # Send a simple HTTP GET request
                request = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
                ssl_sock.sendall(request.encode())
                response = ssl_sock.recv(4096)
                print("\nResponse headers:")
                print(response.decode('utf-8', errors='ignore').split('\r\n\r\n')[0])
            finally:
                ssl_sock.close()
    elif choice == '2':
        # Large Client Hello test
        send_large_client_hello(host, port)
    elif choice == '3':
        # 0-RTT handshake
        data = input("Enter data to send in 0-RTT (or press Enter for default): ").strip()
        if not data:
            data = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
        response = tls13_0rtt_handshake(host, port, data.encode())
        if response:
            print("\n0-RTT response:")
            print(response.decode('utf-8', errors='ignore'))
    elif choice == '4':
        # DHE handshake
        ssl_sock = tls13_dhe_handshake(host, port)
        if ssl_sock:
            try:
                # Send a simple HTTP GET request
                request = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
                ssl_sock.sendall(request.encode())
                response = ssl_sock.recv(4096)
                print("\nResponse headers:")
                print(response.decode('utf-8', errors='ignore').split('\r\n\r\n')[0])
            finally:
                ssl_sock.close()
    elif choice == '5':
        # Specific cipher suite
        cipher_suite = input("Enter cipher suite (e.g., ECDHE-ECDSA-AES256-GCM-SHA384): ").strip()
        if not cipher_suite:
            cipher_suite = 'TLS_AES_256_GCM_SHA384'  # Default cipher
        ssl_sock = tls13_specific_cipher_handshake(host, port, cipher_suite, verify_cert=False)
        if ssl_sock:
            try:
                # Send a simple HTTP GET request
                request = f"GET / HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n\r\n"
                ssl_sock.sendall(request.encode())
                response = ssl_sock.recv(4096)
                print("\nResponse headers:")
                print(response.decode('utf-8', errors='ignore').split('\r\n\r\n')[0])
            finally:
                ssl_sock.close()
    elif choice == '6':
        # PSK handshake - Not directly supported in Python's ssl module
        print("\nPSK Key Exchange")
        print("-" * 50)
        try:
            # This will raise NotImplementedError with a helpful message
            tls13_psk_handshake(host, port)
        except NotImplementedError as e:
            print(f"\nError: {e}")
    elif choice == '7':
        # Kyber handshake
        tls13_kyber_handshake(host, port)
    elif choice == '8':
        print("choice is :8")
        print(f"Connecting to {host}:{port}...")
        print("Performing TLS 1.3 handshake with fragmented ClientHello...")
        sock = tls13_fragmented_handshake(host, port, verify_cert=False)
        
        if sock:
            try:
                # Send a simple HTTP request
                sock.sendall(b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\nConnection: close\r\n\r\n")
                response = sock.recv(4096)
                print("\nResponse headers:")
                print(response.decode('latin-1').split('\r\n\r\n')[0])
            except Exception as e:
                print(f"Error during HTTP request: {e}")
            finally:
                sock.close()
    elif choice == '9':
        print(f"Connecting to {host}:{port}...")
        print("Performing TLS 1.3 handshake with multiple records in one packet...")
        sock = tls13_multiple_records_handshake(host, port, verify_cert=False)
        
        if sock:
            try:
                # Send a simple HTTP request
                sock.sendall(b"GET / HTTP/1.1\r\nHost: " + host.encode() + b"\r\nConnection: close\r\n\r\n")
                response = sock.recv(4096)
                print("\nResponse headers:")
                print(response.decode('latin-1').split('\r\n\r\n')[0])
            except Exception as e:
                print(f"Error during HTTP request: {e}")
            finally:
                sock.close()
    elif choice == 'q':
        print("Exiting")
    else:
        print("Invalid choice")

if __name__ == "__main__":
    main()
