// redirect serves an HTTPS endpoint that redirects every request to a target
// URL. It is used to prove that federation clients do not follow downgrade
// redirects to plaintext.
package main

import (
	"flag"
	"log"
	"net/http"
	"time"
)

func main() {
	addr := flag.String("addr", "", "listen address")
	cert := flag.String("cert", "", "TLS certificate")
	key := flag.String("key", "", "TLS key")
	location := flag.String("location", "", "redirect target")
	flag.Parse()
	if *addr == "" || *cert == "" || *key == "" || *location == "" {
		log.Fatal("addr, cert, key and location are required")
	}
	server := &http.Server{
		Addr:              *addr,
		ReadHeaderTimeout: 5 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, *location, http.StatusFound)
		}),
	}
	log.Fatal(server.ListenAndServeTLS(*cert, *key))
}
