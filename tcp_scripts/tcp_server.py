#!/usr/bin/env python3
"""
A simple TCP server in Python that demonstrates basic socket programming.
This server listens for incoming connections and echoes messages back to clients.
"""

import socket
import threading
import sys
import time

class TCPServer:
    def __init__(self, host='10.10.10.7', port=8080, default_bytes=100):
        """
        Initialize the TCP server.
        
        Args:
            host (str): Host to bind to (default: 'localhost')
            port (int): Port to listen on (default: 8080)
            default_bytes (int): Default number of bytes to send (default: 100)
        """
        self.host = host
        self.port = port
        self.default_bytes = default_bytes
        self.server_socket = None
        self.running = False
        self.clients = []
        
    def start(self):
        """Start the TCP server."""
        try:
            # Create a TCP socket
            self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            # Set socket options to reuse address
            self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            # Bind the socket to the host and port
            self.server_socket.bind((self.host, self.port))
            
            # Start listening for incoming connections (backlog of 5)
            self.server_socket.listen(5)
            
            self.running = True
            print(f"TCP Server started on {self.host}:{self.port}")
            print("Waiting for connections...")
            
            # Start accepting connections in a separate thread
            accept_thread = threading.Thread(target=self.accept_connections)
            accept_thread.daemon = True
            accept_thread.start()
            
            # Keep the main thread alive
            while self.running:
                time.sleep(1)
                
        except socket.error as e:
            print(f"Socket error: {e}")
        except KeyboardInterrupt:
            print("\nServer shutting down...")
        finally:
            self.stop()
    
    def accept_connections(self):
        """Accept incoming connections and handle them in separate threads."""
        while self.running:
            try:
                # Accept a new connection
                client_socket, client_address = self.server_socket.accept()
                print(f"New connection from {client_address}")
                
                # Add client to the list
                self.clients.append(client_socket)
                
                # Handle the client in a separate thread
                client_thread = threading.Thread(
                    target=self.handle_client,
                    args=(client_socket, client_address)
                )
                client_thread.daemon = True
                client_thread.start()
                
            except socket.error as e:
                if self.running:
                    print(f"Error accepting connection: {e}")
                break
    
    def handle_client(self, client_socket, client_address):
        """
        Handle communication with a connected client.
        
        Args:
            client_socket: The socket object for the client
            client_address: The address of the client
        """
        try:
            # Send welcome message
            welcome_message = f"Welcome to TCP Server! You are connected from {client_address}\n"
            client_socket.send(welcome_message.encode('utf-8'))
            
            while self.running:
                # Receive data from client (buffer size: 1024 bytes)
                data = client_socket.recv(1024)
                
                if not data:
                    # Client disconnected
                    print(f"Client {client_address} disconnected")
                    break
                
                # Decode the received data
                message = data.decode('utf-8').strip()
                print(f"Received from {client_address}: {message}")
                
                # Handle special commands
                if message.lower() == 'exit':
                    response = "Goodbye!\n"
                    client_socket.send(response.encode('utf-8'))
                    break
                elif message.lower() == 'time':
                    response = f"Server time: {time.ctime()}\n"
                elif message.lower() == 'send_default':
                    # Send the default number of bytes
                    num_bytes = self.default_bytes
                    data_to_send = 'X' * num_bytes
                    response = f"Sending default {num_bytes} bytes...\n"
                    client_socket.send(response.encode('utf-8'))
                    client_socket.send(data_to_send.encode('utf-8'))
                    print(f"Sent default {num_bytes} bytes to {client_address}")
                    continue  # Skip the final send since we already sent the data
                elif message.lower().startswith('timeout '):
                    # Simulate connection timeout
                    try:
                        # Extract the timeout duration from the command
                        timeout_str = message[8:].strip()
                        timeout_seconds = float(timeout_str)
                        
                        if timeout_seconds <= 0:
                            response = "Error: Timeout duration must be positive\n"
                        elif timeout_seconds > 60:  # Limit to 60 seconds for safety
                            response = "Error: Maximum timeout duration is 60 seconds\n"
                        else:
                            response = f"Simulating connection timeout for {timeout_seconds} seconds...\n"
                            client_socket.send(response.encode('utf-8'))
                            print(f"Starting timeout simulation for {timeout_seconds} seconds for {client_address}")
                            
                            # Simulate timeout by sleeping
                            time.sleep(timeout_seconds)
                            
                            response = "Timeout simulation complete. Connection may appear unresponsive.\n"
                            client_socket.send(response.encode('utf-8'))
                            print(f"Timeout simulation completed for {client_address}")
                            continue  # Skip the final send since we already sent the data
                    except ValueError:
                        response = "Error: Invalid duration. Usage: timeout <seconds>\n"
                elif message.lower().startswith('send '):
                    # Handle send command with number of bytes
                    try:
                        # Extract the number from the command
                        num_bytes_str = message[5:].strip()
                        num_bytes = int(num_bytes_str)
                        
                        if num_bytes <= 0:
                            response = "Error: Number of bytes must be positive\n"
                        elif num_bytes > 10240:  # Limit to 10KB for safety
                            response = "Error: Maximum allowed bytes is 10240 (10KB)\n"
                        else:
                            # Create data with the specified number of bytes
                            data_to_send = 'X' * num_bytes
                            response = f"Sending {num_bytes} bytes...\n"
                            client_socket.send(response.encode('utf-8'))
                            client_socket.send(data_to_send.encode('utf-8'))
                            print(f"Sent {num_bytes} bytes to {client_address}")
                            continue  # Skip the final send since we already sent the data
                    except ValueError:
                        response = "Error: Invalid number. Usage: send <number_of_bytes>\n"
                elif message.lower() == 'help':
                    response = "Available commands:\n"
                    response += "  - 'exit': Disconnect from server\n"
                    response += "  - 'time': Get server time\n"
                    response += "  - 'send_default': Send default number of bytes\n"
                    response += "  - 'send <bytes>': Send specified number of bytes\n"
                    response += "  - 'timeout <seconds>': Simulate connection timeout\n"
                    response += "  - 'help': Show this help message\n"
                    response += "  - Any other message will be echoed back\n"
                else:
                    # Echo the message back to the client
                    response = f"Echo: {message}\n"
                
                # Send response back to client
                client_socket.send(response.encode('utf-8'))
                
        except socket.error as e:
            print(f"Error handling client {client_address}: {e}")
        finally:
            # Clean up the client connection
            if client_socket in self.clients:
                self.clients.remove(client_socket)
            client_socket.close()
            print(f"Connection closed for {client_address}")
    
    def stop(self):
        """Stop the TCP server and clean up resources."""
        self.running = False
        
        # Close all client connections
        for client_socket in self.clients:
            try:
                client_socket.close()
            except:
                pass
        
        self.clients.clear()
        
        # Close the server socket
        if self.server_socket:
            try:
                self.server_socket.close()
            except:
                pass
        
        print("Server stopped")

def main():
    """Main function to run the TCP server."""
    import argparse
    
    # Set up argument parser
    parser = argparse.ArgumentParser(description='TCP Server with byte sending capability')
    parser.add_argument('--host', default='10.10.10.7', help='Host to bind to (default: 10.10.10.7)')
    parser.add_argument('--port', type=int, default=8080, help='Port to listen on (default: 8080)')
    parser.add_argument('--default-bytes', type=int, default=100, 
                       help='Default number of bytes to send (default: 100)')
    
    args = parser.parse_args()
    
    # Create and start the server
    server = TCPServer(args.host, args.port, args.default_bytes)
    
    try:
        server.start()
    except KeyboardInterrupt:
        print("\nShutting down server...")
    finally:
        server.stop()

if __name__ == "__main__":
    main()
