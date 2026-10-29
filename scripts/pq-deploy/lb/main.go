// lb is a minimal TCP load balancer used by the local HA deployment script.
// It forwards each accepted connection to the first reachable backend and copies
// bytes in both directions. It exists only to exercise server failover on
// loopback; it is not production load-balancing code.
package main

import (
	"flag"
	"io"
	"log"
	"net"
	"strings"
	"sync/atomic"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:18091", "listen address")
	backends := flag.String("backends", "127.0.0.1:18092,127.0.0.1:18093", "comma-separated backends")
	flag.Parse()

	addrs := strings.Split(*backends, ",")
	var next atomic.Uint64

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("listening on %s for backends %v", *listen, addrs)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept: %v", err)
			continue
		}
		go func(conn net.Conn) {
			defer conn.Close()
			start := next.Add(1) - 1
			var upstream net.Conn
			for i := 0; i < len(addrs); i++ {
				addr := addrs[(start+uint64(i))%uint64(len(addrs))]
				upstream, err = net.Dial("tcp", addr)
				if err == nil {
					break
				}
				log.Printf("backend %s unavailable: %v", addr, err)
			}
			if upstream == nil {
				log.Printf("no reachable backend for %s", conn.RemoteAddr())
				return
			}
			defer upstream.Close()

			done := make(chan struct{}, 2)
			go func() { _, _ = io.Copy(upstream, conn); done <- struct{}{} }()
			go func() { _, _ = io.Copy(conn, upstream); done <- struct{}{} }()
			<-done
		}(conn)
	}
}
