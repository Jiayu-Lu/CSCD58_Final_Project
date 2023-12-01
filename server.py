import http.server
from socketserver import socket, TCPServer

PORT = 8000  # You can choose any available port

class MyHttpRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        # This method can be customized to handle GET requests
        return http.server.SimpleHTTPRequestHandler.do_GET(self)

# Set up HTTP server
handler_object = MyHttpRequestHandler
my_server = TCPServer(("", PORT), handler_object)

# Get server IP
host_name = socket.gethostname()
host_ip = socket.gethostbyname(host_name)
print(f"Server started at IP address {host_ip} on port {PORT}")

try:
    # Start server
    my_server.serve_forever()
except KeyboardInterrupt:
    print("Server stopped.")
    my_server.server_close()

