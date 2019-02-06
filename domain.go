
package main

import (
	"regexp"
)

// Regexps to help navigate base domains.  The purpose of this to pull out
// things which are usefully differentiated domains, and also to permit
// ignoring some domains if needed.  Potentially, any domain could be a
// tunnel server, but we would expect integrity in the DNS services at the
// top level, so less likely to be DNS tunnel servers.  It's most useful to
// flag at the registered domain level e.g. to flag DNS tunnels at
// my-domain.co.uk rather than co.uk.  So, this regexp helps differentiate
// the different levels of registry.

// The differentiation is more important on busier domains (like .us and .uk)
// rather than e.g. Cook Islands.  Someone investigating a tunnel on a co.us
// domain wants to be able to differentiate between different companies
// whereas it's probably fine to flag up e.g. co.ck since there's little
// traffic there.
//
// Some domain hierarchies e.g. in-addr.arpa behave differently so it may be
// necessary to ignore these at some point, but for now, this has not been
// needed.

var (
	re = regexp.MustCompile(
		"([^.]+)" + 
			"(\\.(gov|judiciary|police|nhs|co|ac|nic|net|mod|parliament|plc|ltd|sch)\\.uk|" +
			"\\.(fed|isa|nsn|dni|..)\\.us|\\.[^.]+)$")
)

func ExtractDomain(s string) string {
	matched := re.FindStringSubmatch(s)
	if len(matched) < 3 {
		return ""
	} else {
		return matched[1] + matched[2]
	}
}

