package tlsconfig

import (
	"net"
	"net/http"
)

// ListenAndServe serves HTTP/1.1 over the owned TLS boundary. Unlike
// http.Server.ListenAndServeTLS, it never consults server.TLSConfig. Request.TLS
// is not populated by net/http for this owned net.Conn type; applications must
// not use its absence to infer that the request arrived over plaintext.
func (c *Config) ListenAndServe(server *http.Server) error {
	if server == nil || server.TLSConfig != nil {
		return profileError("HTTP server must be non-nil and must not provide TLSConfig")
	}
	addr := server.Addr
	if addr == "" {
		addr = ":https"
	}
	inner, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	secured, err := c.Listener(inner)
	if err != nil {
		inner.Close()
		return err
	}
	defer secured.Close()
	return server.Serve(secured)
}
