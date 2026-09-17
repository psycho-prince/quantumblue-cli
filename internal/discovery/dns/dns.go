package dns

import (
	"context"
	"strings"

	"github.com/miekg/dns"
)

type Record struct {
	Type  string // A|AAAA|CNAME|MX|TXT|NS|CAA|SOA
	Name  string
	Value string
	TTL   uint32
}

type Result struct {
	Domain     string
	Records    []Record
	Subdomains []string
	Errors     []string
}

type Options struct {
	Resolvers []string
}

func Enumerate(ctx context.Context, domain string, opts Options) (*Result, error) {
	result := &Result{
		Domain:     domain,
		Records:    []Record{},
		Subdomains: []string{},
		Errors:     []string{},
	}

	resolvers := opts.Resolvers
	if len(resolvers) == 0 {
		resolvers = []string{"8.8.8.8:53", "1.1.1.1:53"}
	}
	resolver := resolvers[0]

	c := new(dns.Client)

	recordTypes := []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeCNAME, dns.TypeMX, dns.TypeTXT, dns.TypeNS, dns.TypeCAA, dns.TypeSOA}
	fqdn := dns.Fqdn(domain)

	for _, qtype := range recordTypes {
		m := new(dns.Msg)
		m.SetQuestion(fqdn, qtype)

		r, _, err := c.ExchangeContext(ctx, m, resolver)
		if err != nil {
			result.Errors = append(result.Errors, err.Error())
			continue
		}

		for _, ans := range r.Answer {
			header := ans.Header()
			rec := Record{
				Name: strings.TrimSuffix(header.Name, "."),
				TTL:  header.Ttl,
				Type: dns.TypeToString[header.Rrtype],
			}
			
			switch v := ans.(type) {
			case *dns.A:
				rec.Value = v.A.String()
			case *dns.AAAA:
				rec.Value = v.AAAA.String()
			case *dns.CNAME:
				rec.Value = strings.TrimSuffix(v.Target, ".")
				result.Subdomains = append(result.Subdomains, rec.Value) // Naive extraction, better logic needed later
			case *dns.MX:
				rec.Value = strings.TrimSuffix(v.Mx, ".")
			case *dns.TXT:
				rec.Value = strings.Join(v.Txt, " ")
			case *dns.NS:
				rec.Value = strings.TrimSuffix(v.Ns, ".")
			case *dns.CAA:
				rec.Value = v.Value
			case *dns.SOA:
				rec.Value = strings.TrimSuffix(v.Ns, ".")
			}

			if rec.Value != "" {
				result.Records = append(result.Records, rec)
			}
		}
	}

	return result, nil
}
