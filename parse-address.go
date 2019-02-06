
package main

import (
	"strings"
)

// Convert a list of address (as we use in event src/dest to
// (address, port, protocol) tuple.
func ParseAddress(a []string) (string, string, string) {

	var ip, port, proto string

        // Loop through source addresses
        for _, v := range a {

                var cls, addr string
		
                // Split into address class and value parts (if present)
                val_parts := strings.SplitN(v, ":", 2)

                cls = val_parts[0]
                if len(val_parts) > 1 {
                        addr = val_parts[1]
                } else {
                        addr = ""
                }

                // Store in appropriate address values.
                switch {
                case cls == "ipv6":
                        ip = addr
                case cls == "ipv4":
                        ip = addr
                case cls == "tcp":
                        port = addr
                        proto = "tcp"
                case cls == "udp":
                        port = addr
                        proto = "udp"
                case cls == "icmp":
                        port = ""
                        proto = "icmp"
                }

        }

	return ip, port, proto

}

