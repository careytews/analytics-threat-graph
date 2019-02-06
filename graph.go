package main

import (
        dt "github.com/trustnetworks/analytics-common/datatypes"
        "time"
	"strings"
	"regexp"
)

var (
	ipAddrRegex = regexp.MustCompile("^[0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+$")
)

type State struct {
	Count int
	Times map[time.Time]bool
}

func NewState() *State {
	return &State{
		Count: 0, Times: map[time.Time]bool{},
	}
}

type Node struct {
	Name string
	Group string
}

type Edge struct {
	Source string
	Destination string
	Group string
}

type Summary struct {
	Nodes map[Node]*State
	Edges map[Edge]*State
}

func NewSummary() Summary {
	return Summary{
		Nodes: map[Node]*State{},
		Edges: map[Edge]*State{},
	}
}

func (this *Summary) ToGraph() ([]interface{}, error) {
        elements := []interface{}{}

	for k, v := range this.Nodes {
		tss := dt.NewTimestampSet("HOUR")
		for tm, _ := range v.Times {
			ts := uint64(tm.Unix())
			tss.Add(ts)
		}
                elements = append(elements,
                        dt.NewEntity(k.Name, k.Group).
				SetProperty("count", v.Count).
				SetProperty("time", tss))
	}

	for k, v := range this.Edges {
		tss := dt.NewTimestampSet("HOUR")
		for tm, _ := range v.Times {
			ts := uint64(tm.Unix())
			tss.Add(ts)
		}
                elements = append(elements,
                        dt.NewEdge(k.Source, k.Destination, k.Group).
				SetProperty("count", v.Count).
				SetProperty("time", tss))
	}

	return elements, nil
	
}

type Summarisable interface {
	Update(*Summary, time.Time)
}

func (this *Node) Update(s *Summary, tm time.Time) {
	if _, ok := s.Nodes[*this]; !ok {
		s.Nodes[*this] = NewState()
	}
	s.Nodes[*this].Count += 1
	s.Nodes[*this].Times[tm] = true
}

func (this *Edge) Update(s *Summary, tm time.Time) {
	if _, ok := s.Edges[*this]; !ok {
		s.Edges[*this] = NewState()
	}
	s.Edges[*this].Count += 1
	s.Edges[*this].Times[tm] = true
}

// Handle a single JSON object.
func DescribeThreatElements(e dt.Event) ([]Summarisable, time.Time, error) {

        device  := e.Device
        network := e.Network

        // Build the timestamp
        tm, _ := time.Parse("2006-01-02T15:04:05.000Z", e.Time)

	tm = tm.Round(time.Second)

	_ = device
	_ = network
	_ = tm

	sip, sport, sproto := ParseAddress(e.Src)
	dip, dport, dproto := ParseAddress(e.Dest)

	if sip == "" || dip == "" { return nil, tm, nil }

	_ = sport
	_ = sproto
	_ = dport
	_ = dproto

	elts := []Summarisable{}

	// Add ipflow edge between two IPs.
	elts = append(elts, &Node{sip, "ip"})
	elts = append(elts, &Node{dip, "ip"})
	elts = append(elts, &Edge{sip, dip, "ipflow"})

	if e.Origin != "" {
		elts = append(elts, &Node{e.Device, "device"})
		if e.Origin == "device" {
			elts = append(elts, &Edge{e.Device, sip, "hasip"})
		} else if e.Origin == "network" {
			elts = append(elts, &Edge{e.Device, dip, "hasip"})
		}
	}

	if e.Action == "dns_message" && e.DnsMessage != nil &&
		e.DnsMessage.Type == "query" && e.DnsMessage.Query != nil {
		for _, v := range e.DnsMessage.Query {
			if v.Name != "" {
				elts = append(elts,
					&Node{v.Name, "hostname"})
				elts = append(elts,
					&Edge{sip, v.Name, "dnsquery"})

				par := ExtractDomain(v.Name)
				if par != "" {
					elts = append(elts,
						&Node{par, "domain"})
					elts = append(elts,
						&Edge{v.Name, par, "indomain"})

				}

			}
		}
	}

	// 
	if e.Action == "dns_message" && e.DnsMessage != nil &&
		e.DnsMessage.Type == "response" && e.DnsMessage.Answer != nil {
		for _, v := range e.DnsMessage.Answer {

			if v.Name != "" && v.Address != "" {

				elts = append(elts,
					&Node{v.Name, "hostname"})
				elts = append(elts,
					&Node{v.Address, "ip"})
				elts = append(elts,
					&Edge{v.Name, v.Address,
						"dns"})
				
				par := ExtractDomain(v.Name)
				if par != "" {
					elts = append(elts,
						&Node{par, "domain"})
					elts = append(elts,
						&Edge{v.Name, par, "indomain"})
				}
					
			}
		}
	}

	if e.Action == "http_request" && e.HttpRequest != nil {
		host := ""
		ua := ""
		if e.HttpRequest.Header != nil {
			host = e.HttpRequest.Header["Host"]
			ua = e.HttpRequest.Header["User-Agent"]
		}

		if ua != "" {
			elts = append(elts,
				&Edge{sip, ua, "useragent"})
		}

		if host != "" {

			// FIXME: Look at this.
			elts = append(elts,
				&Node{host, "server"})
			elts = append(elts,
				&Edge{sip, host, "webrequest"})
			elts = append(elts,
				&Edge{dip, host, "serves"})

			hostpart := host
			ix := strings.IndexAny(hostpart, ":")
			if ix >= 0 {
				hostpart = hostpart[:ix]
			}

			if !ipAddrRegex.MatchString(hostpart) {

				domain := ExtractDomain(hostpart)
				if domain != "" {
					elts = append(elts,
						&Node{domain, "domain"})
					elts = append(elts,
						&Edge{host, domain, "indomain"})
				}

			}

		}
	}

	return elts, tm, nil
        
}

func DescribeThreatGraph(e dt.Event) (interface{}, error) {

	s := NewSummary()

	res, tm, _ := DescribeThreatElements(e)
	for _, v := range res {
		v.Update(&s, tm)
	}

	g, _ := s.ToGraph()

	return g, nil

}

/*

func main() {

	file := "data.json"
	f, err := os.Open(file)
	if err != nil {
		fmt.Printf("Couldn't read %s: %s\n", file, err.Error())
		os.Exit(1)
	}
	data, err := ioutil.ReadAll(f)
	if err != nil {
		fmt.Printf("Couldn't read file: %s\n", err.Error())
		os.Exit(1)
	}
	f.Close()

	var es []dt.Event
	err = json.Unmarshal(data, &es)
	if err != nil {
		fmt.Printf("Couldn't unmarshal JSON from file: %s\n",
			err.Error())
	}

	for _, v := range es {

		g, _  := DescribeThreatGraph(v)

		b, _ := json.MarshalIndent(g, "", "  ")
		fmt.Println(string(b))

	}

}

*/
