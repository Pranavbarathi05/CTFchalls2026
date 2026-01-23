#!/usr/bin/env python3
"""
Simple HTTP server for Caesar's Pizza Menu challenge
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import os

class MenuHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/' or self.path == '/menu':
            self.send_response(200)
            self.send_header('Content-type', 'text/plain')
            self.end_headers()
            
            response = """=== Caesar's Pizza Menu Challenge ===

Welcome to Caesar's Pizza Palace!

We have an encrypted menu that contains our secret VIP item.
Can you decrypt it to find the flag?

Encrypted Menu:
"""
            # Read and serve the encrypted menu
            if os.path.exists('/app/encrypted_menu.txt'):
                with open('/app/encrypted_menu.txt', 'r') as f:
                    encrypted = f.read()
                response += encrypted
            else:
                response += "[Menu file not found]"
            
            response += """

Hint: Caesar liked to shift letters in his messages...
Try downloading and decrypting the menu!

Available endpoints:
- GET / or /menu : View this page
- GET /encrypted_menu.txt : Download the encrypted menu file
"""
            self.wfile.write(response.encode())
            
        elif self.path == '/encrypted_menu.txt':
            if os.path.exists('/app/encrypted_menu.txt'):
                self.send_response(200)
                self.send_header('Content-type', 'text/plain')
                self.send_header('Content-Disposition', 'attachment; filename="encrypted_menu.txt"')
                self.end_headers()
                
                with open('/app/encrypted_menu.txt', 'rb') as f:
                    self.wfile.write(f.read())
            else:
                self.send_response(404)
                self.end_headers()
                self.wfile.write(b'File not found')
        else:
            self.send_response(404)
            self.end_headers()
            self.wfile.write(b'404 - Not Found')
    
    def log_message(self, format, *args):
        # Custom logging
        print(f"[{self.address_string()}] {format % args}")

def run_server(port=8001):
    server_address = ('', port)
    httpd = HTTPServer(server_address, MenuHandler)
    print(f'Starting Caesar\'s Pizza Menu server on port {port}...')
    httpd.serve_forever()

if __name__ == '__main__':
    run_server()
