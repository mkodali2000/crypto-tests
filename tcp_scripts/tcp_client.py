#!/usr/bin/env python3
"""
A simple TCP client in Python to test the TCP server.
"""

import socket
import sys
import threading

class TCPClient:
    def __init__(self, host='10.10.10.7', port=8080):
        """
        Initialize the TCP client.
        
        Args:
            host (str): Server host to connect to (default: 'localhost')
            port (int): Server port to connect to (default: 8080)
        """
        self.host = host
        self.port = port
        self.client_socket = None
        self.connected = False
        
    def connect(self):
        """Connect to the TCP server."""
        try:
            # Create a TCP socket
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            
            # Connect to the server
            self.client_socket.connect((self.host, self.port))
            self.connected = True
            print(f"Connected to server at {self.host}:{self.port}")
            
            # Start a thread to receive messages from server
            receive_thread = threading.Thread(target=self.receive_messages)
            receive_thread.daemon = True
            receive_thread.start()
            
            return True
            
        except socket.error as e:
            print(f"Connection error: {e}")
            return False
    
    def send_message(self, message):
        """
        Send a message to the server.
        
        Args:
            message (str): Message to send
        """
        if self.connected and self.client_socket:
            try:
                self.client_socket.send(message.encode('utf-8'))
            except socket.error as e:
                print(f"Error sending message: {e}")
                self.connected = False
    
    def receive_messages(self):
        """Receive messages from the server."""
        while self.connected:
            try:
                # Receive data from server
                data = self.client_socket.recv(1024)
                
                if not data:
                    # Server disconnected
                    print("Server disconnected")
                    self.connected = False
                    break
                
                # Decode and print the received message
                message = data.decode('utf-8')
                print(f"Server: {message.strip()}")
                
            except socket.error as e:
                if self.connected:
                    print(f"Error receiving message: {e}")
                self.connected = False
                break
    
    def disconnect(self):
        """Disconnect from the server."""
        self.connected = False
        if self.client_socket:
            self.client_socket.close()
        print("Disconnected from server")

def main():
    """Main function to run the TCP client."""
    # You can customize the host and port here
    host = '10.10.10.7'
    port = 8080
    
    # Create and connect the client
    client = TCPClient(host, port)
    
    if not client.connect():
        print("Failed to connect to server")
        return
    
    print("Type messages to send to the server (type 'exit' to quit):")
    
    try:
        while client.connected:
            # Get user input
            message = input("> ")
            
            if message.lower() == 'exit':
                break
            
            # Send the message
            client.send_message(message)
            
    except KeyboardInterrupt:
        print("\nExiting...")
    finally:
        client.disconnect()

if __name__ == "__main__":
    main()
