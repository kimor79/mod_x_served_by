X-Served-By: hostname
=====================

This is an Apache module to add an `X-Served-By' header to the response whose
value is the hostname of the system. [*]

Add this to the server or virtual host config to enable the X-Served-By module:

XServedByEnabled On

The header name can be set via the XServedByHeader parameter:

XServedByHeader "X-My-Hostname"


* Yes, this can be achieved with mod_headers and environment variables.
