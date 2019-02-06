
package main

import (
	"testing"
)

func TestDomain(t *testing.T) {

	type test struct {
		i string
		o string
	}
	
	tests := []test{
		{i: "www.bunchy.co.uk", o: "bunchy.co.uk"},
		{i: "www2.www.bunchy.co.uk", o: "bunchy.co.uk"},
		{i: "www.acid-house.bunchy.com", o: "bunchy.com"},
		{i: "www.gov.uk", o: "www.gov.uk",},
		{i: "das.house.de", o: "house.de"},
		{i: "das.house", o: "das.house"},
	}

	for _, v := range tests {

		d := ExtractDomain(v. i)
		if d != v.o {
			t.Errorf("%s -> %s (%s)", v.i, v.o, d)

		}
	}

}

