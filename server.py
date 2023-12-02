import http.server
from socketserver import socket, TCPServer
from settings import SERVER_PORT


class MyHttpRequestHandler(http.server.SimpleHTTPRequestHandler):
    def do_GET(self):
        # This method can be customized to handle GET requests
        return http.server.SimpleHTTPRequestHandler.do_GET(self)

# Set up HTTP server
handler_object = MyHttpRequestHandler
my_server = TCPServer(("", SERVER_PORT), handler_object)

# Get server IP
host_name = socket.gethostname()
host_ip = socket.gethostbyname(host_name)
print(f"Server started at IP address {host_ip} on port {SERVER_PORT}")

try:
    # Start server
    my_server.serve_forever()
except KeyboardInterrupt:
    print("Server stopped.")
    my_server.server_close()

