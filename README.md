# rsdirect

A tiny web server that serves 301 redirects based on the host from which the server was reached (as specified in the request headers).

A JSON config file of the form:
```json
{
  "some.hostname.com": "https://destination-url.com/",
  "some.other.hostname.org": "https://other-dest.com/with/some/path"
}
```
...must be supplied as a command-line argument.

Additionally, TLS is supported, and can be enabled by supplying public key and certificate files via the respective command-line arguments.
