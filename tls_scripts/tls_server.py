import socket
from datetime import datetime

def start_tcp_server(host='0.0.0.0', port=8080):
    # Create a TCP socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        sock.listen(5)
        print(f"TCP Server listening on {host}:{port}")
        print("Server is ready to accept connections from any IP address")
        
        while True:
            try:
                # Accept new connection
                conn, addr = sock.accept()
                print(f"Connection from {addr}")
                
                try:
                    # Send welcome message
                    welcome_msg = f"Welcome! Connected to TCP Server at {datetime.now().strftime('%H:%M:%S')}\n"
                    conn.sendall(welcome_msg.encode())
                    print(f"Sent welcome message to {addr}")
                    
                    # Send multiple records
                    for i in range(5):
                        message = f"Record {i+1} - Server time: {datetime.now().strftime('%H:%M:%S')}\n"
                        conn.sendall(message.encode())
                        print(f"Sent: {message.strip()}")
                    
                    # Wait for client to acknowledge
                    data = conn.recv(1024)
                    if data:
                        print(f"Received from client {addr}: {data.decode().strip()}")
                    
                except Exception as e:
                    print(f"Error handling client {addr}: {e}")
                finally:
                    conn.shutdown(socket.SHUT_RDWR)
                    conn.close()
                    print(f"Connection closed with {addr}")
                    
            except Exception as e:
                print(f"Error: {e}")
                continue

if __name__ == "__main__":
    start_tcp_server()

