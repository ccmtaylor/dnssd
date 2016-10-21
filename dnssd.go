package dnssd

import (
	"container/ring"
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"
)

type Dialer interface {
	Dial(network, address string) (net.Conn, error)
	DialContext(ctx context.Context, network, addr string) (net.Conn, error)
}

type Opts struct {
	TTL          time.Duration
	Dialer       Dialer
	RoundTripper http.RoundTripper
	LookupSRV    func(service, proto, name string) (cname string, addrs []*net.SRV, err error)
	LookupIP     func(host string) (ips []net.IP, err error)
}

// New returns a new DNSSD with the that performs SRV resolution for the
// given host with the provided opts.
// New returns an error, if SRV lookup for host fails
// Defaults are as follows:
// If opts.Dialer is nil, a default net.Dialer is used.
// If opts.RoundTripper is nil, http.DefaultTransport is used.
// If opts.TTL is zero, a TTL of 15 seconds is used.
// If opts.LookupSRV is nil, net.LookupSRV is used.
// If opts.LookupIP is nil, net.LookupIP is used.
func New(host string, opts Opts) (*DNSSD, error) {
	c, err := initialize(host, opts)
	if err == nil {
		go func() {
			timer := time.Tick(c.ttl)
			for {
				<-timer
				addrs, err := c.refresh()
				if err != nil {
					// TODO: counter
					continue
				}
				c.replace(addrs)
			}
		}()
	}
	return c, err
}

func initialize(host string, opts Opts) (*DNSSD, error) {
	c := DNSSD{
		host:      host,
		dialer:    opts.Dialer,
		rt:        opts.RoundTripper,
		ttl:       opts.TTL,
		lookupSRV: opts.LookupSRV,
		lookupIP:  opts.LookupIP,
	}
	if c.ttl == 0 {
		c.ttl = 15 * time.Second
	}
	if c.dialer == nil {
		c.dialer = &net.Dialer{}
	}
	if c.rt == nil {
		c.rt = http.DefaultTransport
	}
	if c.lookupSRV == nil {
		c.lookupSRV = net.LookupSRV
	}
	if c.lookupIP == nil {
		c.lookupIP = net.LookupIP
	}
	addrs, err := c.refresh()
	if err != nil {
		return nil, err
	}
	c.replace(addrs)
	return &c, nil
}

type ipport struct {
	ip   net.IP
	port uint16
}

func (i ipport) String() string {
	return net.JoinHostPort(i.ip.String(), fmt.Sprint(i.port))
}

type DNSSD struct {
	mtx       sync.Mutex
	addrs     *ring.Ring
	host      string
	dialer    Dialer
	rt        http.RoundTripper
	ttl       time.Duration
	lookupSRV func(service, proto, name string) (cname string, addrs []*net.SRV, err error)
	lookupIP  func(host string) (ips []net.IP, err error)
}

func (c *DNSSD) next() ipport {
	c.mtx.Lock()
	defer c.mtx.Unlock()
	c.addrs = c.addrs.Next()
	return c.addrs.Value.(ipport)
}

func (c *DNSSD) replace(addrs []ipport) {
	r := ring.New(len(addrs))
	for _, addr := range addrs {
		r.Value = addr
		r = r.Next()
	}
	c.mtx.Lock()
	defer c.mtx.Unlock()
	c.addrs = r
}

func (c *DNSSD) refresh() ([]ipport, error) {
	_, srvs, err := c.lookupSRV("", "", c.host)
	if err != nil {
		return []ipport{}, err
	}
	wg := sync.WaitGroup{}
	ipports := make(chan ipport)
	for _, srv := range srvs {
		wg.Add(1)
		go func(srv *net.SRV) {
			defer wg.Done()
			ips, err := c.lookupIP(srv.Target)
			if err != nil {
				// TODO: counter
				return
			}
			for _, ip := range ips {
				ipports <- ipport{ip, srv.Port}
			}
		}(srv)
	}
	go func() {
		wg.Wait()
		close(ipports)
	}()
	addrs := make([]ipport, 0, len(srvs))
	for addr := range ipports {
		addrs = append(addrs, addr)
	}
	if len(addrs) == 0 {
		err = fmt.Errorf("no results for %q", c.host)
	}
	return addrs, err
}

func (c *DNSSD) Dial(network, addr string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if host != c.host {
		return c.dialer.Dial(network, host)
	}
	return c.dialer.Dial(network, c.next().String())
}

func (c *DNSSD) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	if host != c.host {
		return c.dialer.DialContext(ctx, network, host)
	}
	return c.dialer.DialContext(ctx, network, c.next().String())
}

func (c *DNSSD) RoundTrip(r *http.Request) (*http.Response, error) {
	host, _, err := net.SplitHostPort(r.URL.Host)
	if err != nil {
		host = r.URL.Host
	}
	if host != c.host {
		return c.rt.RoundTrip(r)
	}
	url := *r.URL
	url.Host = c.next().String()
	req := *r
	req.URL = &url
	return c.rt.RoundTrip(&req)
}
