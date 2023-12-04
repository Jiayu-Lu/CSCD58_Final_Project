Module CSCD58_Final_Project.server
==================================

Functions
---------

    
`start_server()`
:   

Classes
-------

`MyHttpRequestHandler(*args, directory=None, **kwargs)`
:   Simple HTTP request handler with GET and HEAD commands.
    
    This serves files from the current directory and any of its
    subdirectories.  The MIME type for files is determined by
    calling the .guess_type() method.
    
    The GET and HEAD requests are identical except that the HEAD
    request omits the actual contents of the file.

    ### Ancestors (in MRO)

    * http.server.SimpleHTTPRequestHandler
    * http.server.BaseHTTPRequestHandler
    * socketserver.StreamRequestHandler
    * socketserver.BaseRequestHandler

    ### Methods

    `do_GET(self)`
    :   Serve a GET request.