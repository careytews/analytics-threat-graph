
package main

import (
	"testing"
	"encoding/json"
	dt "github.com/trustnetworks/analytics-common/datatypes"
	"reflect"
)

type Check func(*testing.T, dt.Bundle)

func RunChecks(t *testing.T, e dt.Event, r []dt.Bundle) {

	g, err := DescribeThreatGraph(e)
	if err != nil {
		t.Errorf("Couldn't describe graph: %s",
			err.Error())
	}
	enc, err := json.Marshal(g)
	if err != nil {
		t.Errorf("Couldn't marshal graph: %s",
			err.Error())
	}

	enc2, err := json.Marshal(r)
	if err != nil {
		t.Errorf("Couldn't marshal graph: %s",
			err.Error())
	}
	

	if string(enc) != string(enc2) {
		t.Errorf("Expected doesn't match generated")
	}
}

func Compare(t *testing.T, in string, exp []Summarisable, exper string) {
	
	var e dt.Event
	err := json.Unmarshal([]byte(in), &e)
	if err != nil {
		t.Errorf("Couldn't decode JSON: %s", err.Error())
	}

	se, _, err := DescribeThreatElements(e)

	for i, _ := range se {

		if reflect.DeepEqual(se[i], exp[i]) == false {
			t.Errorf("Expected doesn't match generated: %s, %s",
				se[i], exp[i])

		}
	}

	if len(se) != len(exp) {
		t.Errorf("Expected doesn't match generated: %d elements != %d",
			len(se), len(exp))
	}
	
}


func TestGraph(t *testing.T) {

	// Case: HTTP request.
	in1 := `
{"network":"test-lan","origin":"device","dest":["ipv4:93.184.216.34","tcp:80","http"],"device":"debug","time":"2018-05-21T11:03:22.634Z","src":["ipv4:10.0.2.15","tcp:34060","http"],"http_request":{"header":{"User-Agent":"Wget\/1.19.5 (linux-gnu)","Accept":"*\/*","Accept-Encoding":"identity","Host":"www.example.org","Connection":"Keep-Alive"},"method":"GET"},"action":"http_request","id":"61106e53-a115-48bf-c881-e68619221236","url":"http:\/\/www.example.org\/"}
`

	exp1 := []Summarisable{

		// IP flow info
		&Node{"10.0.2.15", "ip"},
		&Node{"93.184.216.34", "ip"},
		&Edge{"10.0.2.15", "93.184.216.34", "ipflow"},

		// Device
		&Node{"debug", "device"},
		&Edge{"debug", "10.0.2.15", "hasip"},

		// UA
		&Edge{"10.0.2.15", "Wget/1.19.5 (linux-gnu)", "useragent"},

		// Server information.
		&Node{"www.example.org", "server"},
		&Edge{"10.0.2.15", "www.example.org", "webrequest"},
		&Edge{"93.184.216.34", "www.example.org", "serves"},

		// Domain information
		&Node{"example.org", "domain"},
		&Edge{"www.example.org", "example.org", "indomain"},
		
	}

	Compare(t, in1, exp1, "exp1")

	// Case: DNS query
	in2 := `
{"time":"2018-05-21T09:19:10.045Z","id":"d346b188-e2c0-4e08-ce64-4528b33d6358","dns_message":{"query":[{"type":"A","class":"IN","name":"www.example.org"}],"answer":[],"type":"query"},"action":"dns_message","dest":["ipv4:8.8.8.8","udp:53","dns"],"network":"test-lan","origin":"device","src":["ipv4:10.0.2.15","udp:45465","dns"],"device":"debug"}
`
	exp2 := []Summarisable{

		// IP flow info
		&Node{"10.0.2.15", "ip"},
		&Node{"8.8.8.8", "ip"},
		&Edge{"10.0.2.15", "8.8.8.8", "ipflow"},

		// Device
		&Node{"debug", "device"},
		&Edge{"debug", "10.0.2.15", "hasip"},

		// DNS query info
		&Node{"www.example.org", "hostname"},
		&Edge{"10.0.2.15", "www.example.org", "dnsquery"},

		// Domain
		&Node{"example.org", "domain"},
		&Edge{"www.example.org", "example.org", "indomain"},
		
	}

	Compare(t, in2, exp2, "exp2")

	// Case: Host takes form host:port
	in3 := `
{"network":"test-lan","dest":["ipv4:93.184.216.34","tcp:80","http"],"device":"debug","origin":"device","time":"2018-05-21T11:03:22.634Z","src":["ipv4:10.0.2.15","tcp:34060","http"],"http_request":{"header":{"User-Agent":"Wget\/1.19.5 (linux-gnu)","Accept":"*\/*","Accept-Encoding":"identity","Host":"www.example.org:1280","Connection":"Keep-Alive"},"method":"GET"},"action":"http_request","id":"61106e53-a115-48bf-c881-e68619221236","url":"http:\/\/www.example.org\/"}
`

	exp3 := []Summarisable{

		// IP flow info
		&Node{"10.0.2.15", "ip"},
		&Node{"93.184.216.34", "ip"},
		&Edge{"10.0.2.15", "93.184.216.34", "ipflow"},

		// Device
		&Node{"debug", "device"},
		&Edge{"debug", "10.0.2.15", "hasip"},

		// UA
		&Edge{"10.0.2.15", "Wget/1.19.5 (linux-gnu)", "useragent"},

		// Server information.
		&Node{"www.example.org:1280", "server"},
		&Edge{"10.0.2.15", "www.example.org:1280", "webrequest"},
		&Edge{"93.184.216.34", "www.example.org:1280", "serves"},

		// Domain
		&Node{"example.org", "domain"},
		&Edge{"www.example.org:1280", "example.org", "indomain"},

	}

	Compare(t, in3, exp3, "exp3")

	// Case: DNS response
	in4 := `
{"time":"2018-05-21T09:19:10.045Z","id":"d346b188-e2c0-4e08-ce64-4528b33d6358","dns_message":{"query":[{"type":"A","class":"IN","name":"www.example.org"}],"answer":[{"type":"A","class":"IN","name":"www.example.org","address":"9.10.11.12"}],"type":"response"},"action":"dns_message","dest":["ipv4:8.8.8.8","udp:53","dns"],"network":"test-lan","origin":"device","src":["ipv4:10.0.2.15","udp:45465","dns"],"device":"debug"}
`
	exp4 := []Summarisable{

		// IP flow info
		&Node{"10.0.2.15", "ip"},
		&Node{"8.8.8.8", "ip"},
		&Edge{"10.0.2.15", "8.8.8.8", "ipflow"},

		// Device
		&Node{"debug", "device"},
		&Edge{"debug", "10.0.2.15", "hasip"},

		// DNS response
		&Node{"www.example.org", "hostname"},
		&Node{"9.10.11.12", "ip"},
		&Edge{"www.example.org", "9.10.11.12", "dns"},

		// Domain
		&Node{"example.org", "domain"},
		&Edge{"www.example.org", "example.org", "indomain"},

	}

	Compare(t, in4, exp4, "exp4")

	// Case: HTTP request to IP:port
	in5 := `
{"network":"test-lan","origin":"device","dest":["ipv4:93.184.216.34","tcp:80","http"],"device":"debug","time":"2018-05-21T11:03:22.634Z","src":["ipv4:10.0.2.15","tcp:34060","http"],"http_request":{"header":{"User-Agent":"Wget\/1.19.5 (linux-gnu)","Accept":"*\/*","Accept-Encoding":"identity","Host":"146.182.91.151:1280","Connection":"Keep-Alive"},"method":"GET"},"action":"http_request","id":"61106e53-a115-48bf-c881-e68619221236","url":"http:\/\/www.example.org\/"}
`

	exp5 := []Summarisable{

		// IP flow info
		&Node{"10.0.2.15", "ip"},
		&Node{"93.184.216.34", "ip"},
		&Edge{"10.0.2.15", "93.184.216.34", "ipflow"},

		// Device
		&Node{"debug", "device"},
		&Edge{"debug", "10.0.2.15", "hasip"},

		// UA
		&Edge{"10.0.2.15", "Wget/1.19.5 (linux-gnu)", "useragent"},

		// Server information.
		&Node{"146.182.91.151:1280", "server"},
		&Edge{"10.0.2.15", "146.182.91.151:1280", "webrequest"},
		&Edge{"93.184.216.34", "146.182.91.151:1280", "serves"},

		// No domain info

	}

	Compare(t, in5, exp5, "exp5")

	// Case: HTTP request to IP address, no port
	in6 := `
{"network":"test-lan","origin":"device","dest":["ipv4:93.184.216.34","tcp:80","http"],"device":"debug","time":"2018-05-21T11:03:22.634Z","src":["ipv4:10.0.2.15","tcp:34060","http"],"http_request":{"header":{"User-Agent":"Wget\/1.19.5 (linux-gnu)","Accept":"*\/*","Accept-Encoding":"identity","Host":"146.182.91.151","Connection":"Keep-Alive"},"method":"GET"},"action":"http_request","id":"61106e53-a115-48bf-c881-e68619221236","url":"http:\/\/www.example.org\/"}
`

	exp6 := []Summarisable{

		// IP flow info
		&Node{"10.0.2.15", "ip"},
		&Node{"93.184.216.34", "ip"},
		&Edge{"10.0.2.15", "93.184.216.34", "ipflow"},

		// Device
		&Node{"debug", "device"},
		&Edge{"debug", "10.0.2.15", "hasip"},

		// UA
		&Edge{"10.0.2.15", "Wget/1.19.5 (linux-gnu)", "useragent"},

		// Server information.
		&Node{"146.182.91.151", "server"},
		&Edge{"10.0.2.15", "146.182.91.151", "webrequest"},
		&Edge{"93.184.216.34", "146.182.91.151", "serves"},

		// No domain info

	}

	Compare(t, in6, exp6, "exp6")

}

