# rsdirect

A tiny web server that serves 301 redirects based on the host from which the server was reached (as specified in the request headers).

A JSON config file must be supplied via the command line of the following form: 
```json
{
  "some.hostname.com": {
    "dest": "https://destination-url.com/"
  },
  "some.other.hostname.org": {
    "dest": "https://other-dest.com/with/some/path",
    "preserve_src_path": false
  }
}
```
The `preserve_src_path` flag instructs rsdirect to leave the source path intact at the destination; otherwise, rsdirect will redirect to exactly the URL given in the config.
If omitted, `preserve_src_path` is implied to be `true`.

Additionally, TLS is supported, and can be enabled by supplying public key and certificate files via the respective command-line arguments.
