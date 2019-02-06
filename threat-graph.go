
package main

//
// Gaffer loader for the analytics cluster.  Takes events on input queue
// and restructures for loading into Gaffer.  Multiple RDF statements are
// loaded per event.
//
// No output queues are used.
//

import (
	"encoding/json"
	"github.com/prometheus/client_golang/prometheus"
	dt "github.com/trustnetworks/analytics-common/datatypes"
	"github.com/trustnetworks/analytics-common/utils"
	"github.com/trustnetworks/analytics-common/worker"
	"io/ioutil"
	"net/http"
	"os"
	"strings"
	"time"
	"context"
)

const (
	pgm                 = "threat-graph" // Program name
	MaxIdleConns        = 50          // Maximum number of idle connection to leave in pool
	MaxIdleConnsPerHost = 5           // Maximum number of idle connection to leave in pool
	CnxTimeout          = 5           // How long before a connection timesout
	RefreshSecs         = 10          // How many requests to make before we refresh the cnx pool
)

type Batch struct {
	data []Summarisable
	tm time.Time
}

// Worker local state.
type work struct {
	url   string
	queue chan interface{}
	summaryQueue chan Batch

	eventLatency *prometheus.SummaryVec
	recvLabels   prometheus.Labels
}

// Initialisation.
func (s *work) init() error {

	// Get Gaffer location form GAFFER_URL environment variable.
	s.url = utils.Getenv("GAFFER_URL", "http://gaffer-threat:8080/rest/v1")
	s.recvLabels = prometheus.Labels{"store": pgm}
	s.eventLatency = prometheus.NewSummaryVec(
		prometheus.SummaryOpts{
			Name: "event_latency",
			Help: "Latency from cyberprobe to store",
		},
		[]string{"store"},
	)

	prometheus.MustRegister(s.eventLatency)

	return nil

}

// Handle a single JSON object.
func (h *work) Handle(msg []uint8, w *worker.Worker) error {

	var e dt.Event

	// Convert JSON object to internal object.
	err := json.Unmarshal(msg, &e)
	if err != nil {
		utils.Log("Couldn't unmarshal json: %s", err.Error())
		return nil
	}

	// Initialise vertices/edge arrays.
	elements, tm, err := DescribeThreatElements(e)
	if err != nil {
		utils.Log("Couldn't create threat-graph: %s", err.Error())
		return nil
	}

	if elements == nil {
		return nil
	}

	// Send for Gaffer outputting
	h.summaryQueue <- Batch {
		data: elements,
		tm: tm,
	}

	// Record latency of event
	ts := time.Now().UnixNano()
	go h.recordLatency(ts, e)

	if err != nil {
		utils.Log("index failed: %s", err.Error())
		return nil
	}

	return nil

}

func (h *work) recordLatency(ts int64, e dt.Event) {
	eTime, err := time.Parse(time.RFC3339, e.Time)
	if err != nil {
		utils.Log("Date Parse Error: %s", err.Error())
	}
	latency := ts - eTime.UnixNano()
	h.eventLatency.With(h.recvLabels).Observe(float64(latency))
}

func (s *work) output(elements interface{}) error {

	body := &dt.Bundle{
		"class":               "uk.gov.gchq.gaffer.operation.impl.add.AddElements",
		"validate":            true,
		"skipInvalidElements": false,
		"input":               elements,
	}

	s.queue <- body

	return nil

}

func (s *work) sender(client *http.Client) error {

	for {

		b := <-s.queue

		j, err := json.Marshal(&b)
		if err != nil {
			utils.Log("Couldn't marshal json: %s", err.Error())
			return nil
		}

		retries := 50
		for {

			req, _ := http.NewRequest("PUT",
				s.url+"/graph/doOperation/add/elements",
				strings.NewReader(string(j)))
			req.ContentLength = int64(len(j))
			req.Header.Set("Content-Type", "application/json")

			response, err := client.Do(req)
			if err != nil {
				utils.Log("Couldn't make HTTP request: %s",
					err.Error())
				retries--
				if retries <= 0 {
					utils.Log("Give up.")
					break
				} else {
					utils.Log("Retrying...")
					time.Sleep(time.Second)
					continue
				}
			}

			rtn, _ := ioutil.ReadAll(response.Body)
			response.Body.Close()

			if response.StatusCode == 204 {
				break
			}

			utils.Log("Gaffer PUT error, status %d",
				response.Status)
			utils.Log("Error: %s", rtn)
			retries--
			if retries <= 0 {
				utils.Log("Give up.")
				break
			} else {
				utils.Log("Retrying...")
				time.Sleep(time.Second)
			}

		}

	}

	return nil
}

func (s *work) summarise() error {

	sum := NewSummary()

	tck := time.NewTicker(100 * time.Millisecond).C
	
	for {

		select {

			// Get batch from queue
		case ne := <-s.summaryQueue:

			// Add data to summary
			for _, v := range ne.data {
				v.Update(&sum, ne.tm)
				
			}

			// 10 times a second, send summary.
		case <- tck:

			// Send summary to threatgraph
			grp, err := sum.ToGraph()

			// If no graph, just continue
			if len(grp) == 0 {
				continue
			}

			if err == nil {
				s.output(grp)
			}

			// Reset summary
			sum = NewSummary()

		}

	}

	return nil

}

func main() {

	var w worker.QueueWorker
	var s work
	utils.LogPgm = pgm

	s.init()

	s.queue = make(chan interface{}, 100)
	s.summaryQueue = make(chan Batch, 100)

	// Create an HTTP transport and client for Gaffer.
	tp := &http.Transport{
		MaxIdleConnsPerHost: MaxIdleConnsPerHost,
		MaxIdleConns:        MaxIdleConns,
	}
	client := &http.Client{
		Transport: tp,
		Timeout:   CnxTimeout * time.Second,
	}

	// Refresh idle connections every Xs
	go func() {
		for range time.Tick(RefreshSecs * time.Second) {
			tp.CloseIdleConnections()
		}
	}()
	// Create 5 worker senders
	for i := 0; i <= 5; i++ {
		go s.sender(client)
	}

	// Create 5 worker senders
	for i := 0; i <= 5; i++ {
		go s.summarise()
	}

	var input string
	var output []string

	if len(os.Args) > 0 {
		input = os.Args[1]
	}
	if len(os.Args) > 2 {
		output = os.Args[2:]
	}
	
	// context to handle control of subroutines
	ctx := context.Background()
	ctx, cancel := utils.ContextWithSigterm(ctx)
	defer cancel()
	
	err := w.Initialise(ctx, input, output, pgm)
	if err != nil {
		utils.Log("init: %s", err.Error())
		return
	}

	utils.Log("Initialisation complete.")

	// Invoke Wye event handling.
	err = w.Run(ctx, &s)
	if err != nil {
		utils.Log("error: Event handling failed with err: %s", err.Error())
	}

}


