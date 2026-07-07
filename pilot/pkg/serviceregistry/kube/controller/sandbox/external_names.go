package sandbox

import (
	"container/heap"
	"crypto/sha256"
	"net"
	"slices"
	"time"

	"github.com/miekg/dns"
	"istio.io/istio/pkg/kube/krt"
)

type ExternalName struct {
	Hostname  string
	Addresses []string
}

func (e ExternalName) ResourceName() string {
	return e.Hostname
}

type resolveResult struct {
	hostname  string
	addresses []string
	ttl       uint32
	// failed is true when every configured DNS server errored. In that case
	// addresses is empty *not because the record is gone* but because we
	// couldn't ask — callers must preserve previously-known addresses instead
	// of zeroing out the policy IPSet.
	failed bool
}

type entry struct {
	resolveResult
	index        int
	inHeap       bool
	resolving    bool
	creationTime time.Time
	nextRefresh  time.Time
	refs         int
}

type controllerEventType int

const (
	eventAdd controllerEventType = iota
	eventDelete
	eventResolveDone
)

type controllerEvent struct {
	typ      controllerEventType
	hostname string
	result   *resolveResult
}

type externalNamesControllerOptions struct {
	dnsServers []string
}

type externalNamesController struct {
	heap       entryHeap
	records    map[string]*entry
	dnsServers []string

	events      chan controllerEvent
	workerChan  chan string
	workerCount int

	col krt.StaticCollection[ExternalName]
}

func newExternalServiceController(
	opts externalNamesControllerOptions,
) *externalNamesController {
	dnsServers := opts.dnsServers
	if len(dnsServers) == 0 {
		conf, err := dns.ClientConfigFromFile("/etc/resolv.conf")
		if err != nil || len(conf.Servers) == 0 {
			dnsServers = append(dnsServers, "127.0.0.1:53")
		} else {
			for _, server := range conf.Servers {
				port := "53"
				if conf.Port != "" {
					port = conf.Port
				}
				dnsServers = append(dnsServers, net.JoinHostPort(server, port))
			}
		}
	}
	log.Debugf("Using DNS servers: %v", dnsServers)

	c := &externalNamesController{
		heap:        make(entryHeap, 0),
		records:     make(map[string]*entry),
		dnsServers:  dnsServers,
		events:      make(chan controllerEvent, 1024),
		workerChan:  make(chan string, 1024),
		workerCount: 3,
		col:         krt.NewStaticCollection[ExternalName](nil, nil),
	}

	return c
}

func (c *externalNamesController) AsCollection() krt.Collection[ExternalName] {
	return c.col
}

func (c *externalNamesController) Start(stop <-chan struct{}) {
	log.Debugf("External names controller started with %d workers", c.workerCount)
	for i := 0; i < c.workerCount; i++ {
		go c.worker(stop)
	}
	go c.run(stop)
}

func (c *externalNamesController) HandleAdd(hostname string) {
	c.events <- controllerEvent{
		typ:      eventAdd,
		hostname: hostname,
	}
}

func (c *externalNamesController) HandleDelete(hostname string) {
	c.events <- controllerEvent{
		typ:      eventDelete,
		hostname: hostname,
	}
}

func (c *externalNamesController) run(stop <-chan struct{}) {
	timer := time.NewTimer(time.Hour)
	defer timer.Stop()

	for {
		wait := c.dispatchDueEntries()

		if !timer.Stop() {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(wait)

		select {
		case <-stop:
			return

		case ev := <-c.events:
			switch ev.typ {
			case eventAdd:
				c.onAdd(ev.hostname)
			case eventDelete:
				c.onDelete(ev.hostname)
			case eventResolveDone:
				if ev.result != nil {
					c.onResolveDone(*ev.result)
				}
			}

		case <-timer.C:
		}
	}
}

func (c *externalNamesController) onAdd(hostname string) {
	if e, ok := c.records[hostname]; ok {
		e.refs++
		return
	}

	e := &entry{
		index:        -1,
		inHeap:       false,
		resolving:    false,
		creationTime: time.Now(),
		nextRefresh:  time.Now(),
		refs:         1,
		resolveResult: resolveResult{
			hostname: hostname,
		},
	}
	c.records[hostname] = e
	c.pushOrFix(e)
}

func (c *externalNamesController) onDelete(hostname string) {
	e, ok := c.records[hostname]
	if !ok {
		return
	}

	e.refs--
	if e.refs > 0 {
		return
	}

	delete(c.records, hostname)

	if e.inHeap && e.index >= 0 {
		heap.Remove(&c.heap, e.index)
		e.inHeap = false
		e.index = -1
	}
	c.col.DeleteObject(e.hostname)
}

func (c *externalNamesController) dispatchDueEntries() time.Duration {
	now := time.Now()

	for c.heap.Len() > 0 {
		top := c.heap[0]
		if top.nextRefresh.After(now) {
			return top.nextRefresh.Sub(now)
		}

		e := heap.Pop(&c.heap).(*entry)
		e.inHeap = false

		if e.refs <= 0 || e.resolving {
			continue
		}

		e.resolving = true

		select {
		case c.workerChan <- e.hostname:
		default:
			e.resolving = false
			e.nextRefresh = time.Now().Add(time.Second)
			c.pushOrFix(e)
			return time.Second
		}
	}

	return time.Hour
}

func (c *externalNamesController) worker(stop <-chan struct{}) {
	for {
		select {
		case <-stop:
			return
		case hostname := <-c.workerChan:
			res := c.resolveHostname(hostname)
			c.events <- controllerEvent{
				typ:    eventResolveDone,
				result: &res,
			}
		}
	}
}

func (c *externalNamesController) Resolve(hostname string) []string {
	res := c.resolveHostname(hostname)
	// maybe worker is busy, we help to push resolved results
	c.events <- controllerEvent{
		typ:    eventResolveDone,
		result: &res,
	}
	return res.addresses
}

func (c *externalNamesController) FetchOrResolve(ctx krt.HandlerContext, hostname string) []string {
	if resolved := krt.FetchOne(ctx, c.col, krt.FilterKey(hostname)); resolved != nil {
		return resolved.Addresses
	}
	return c.Resolve(hostname)
}

func (c *externalNamesController) resolveHostname(hostname string) resolveResult {
	result := resolveResult{
		hostname: hostname,
		ttl:      3600,
	}

	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(hostname), dns.TypeA)
	client := &dns.Client{Timeout: 2 * time.Second}

	var in *dns.Msg
	var err error
	for _, dnsServer := range c.dnsServers {
		in, _, err = client.Exchange(msg, dnsServer)
		if err != nil {
			continue
		}
		if in != nil {
			break
		}
	}

	if err != nil {
		result.ttl = 60
		result.failed = true
		log.Warnf("Failed to resolve host %s, err: %+v", hostname, err)
		return result
	}

	if in != nil {
		for _, ans := range in.Answer {
			if a, ok := ans.(*dns.A); ok {
				if ans.Header().Ttl < result.ttl {
					result.ttl = ans.Header().Ttl
				}
				result.addresses = append(result.addresses, a.A.String())
			}
		}
	}

	slices.Sort(result.addresses)
	return result
}

func (c *externalNamesController) onResolveDone(res resolveResult) {
	e, ok := c.records[res.hostname]
	if !ok {
		return
	}
	if !e.resolving {
		return
	}
	e.resolving = false
	e.ttl = res.ttl
	e.nextRefresh = computeNextRefresh(e.hostname, res.ttl)

	// DNS-all-fail: keep previous addresses (and previous downstream policy
	// IPSet) until we can resolve again. Reschedule a sooner retry via the
	// short ttl=60 already set in resolveHostname.
	if res.failed {
		c.pushOrFix(e)
		return
	}

	if slices.Equal(res.addresses, e.addresses) {
		c.pushOrFix(e)
		return
	}

	e.addresses = res.addresses
	c.col.UpdateObject(ExternalName{
		Hostname:  e.hostname,
		Addresses: e.addresses,
	})
	c.pushOrFix(e)
	log.Debugf("[%s] -> Addresses:%+v (TTL:%d)", e.hostname, e.addresses, e.ttl)
}

func stableJitter(key string, max time.Duration) time.Duration {
	if max <= 0 {
		return 0
	}

	sum := sha256.Sum256([]byte(key))
	var v uint64
	for i := range 8 {
		v = (v << 8) | uint64(sum[i])
	}
	return time.Duration(v % uint64(max))
}

func computeNextRefresh(hostname string, ttl uint32) time.Time {
	base := refreshInterval(ttl)
	maxJitter := max(min(base/5, 3*time.Second), 0)
	return time.Now().Add(base + stableJitter(hostname, maxJitter))
}

func refreshInterval(ttl uint32) time.Duration {
	interval := max(time.Duration(ttl)*time.Second, 10*time.Second)
	if interval > 5*time.Second {
		interval -= 5 * time.Second
	}
	return interval
}

func (c *externalNamesController) pushOrFix(e *entry) {
	if e.inHeap {
		heap.Fix(&c.heap, e.index)
		return
	}
	heap.Push(&c.heap, e)
	e.inHeap = true
}

type entryHeap []*entry

func (pq entryHeap) Len() int { return len(pq) }

func (pq entryHeap) Less(i, j int) bool {
	return pq[i].nextRefresh.Before(pq[j].nextRefresh)
}

func (pq entryHeap) Swap(i, j int) {
	pq[i], pq[j] = pq[j], pq[i]
	pq[i].index = i
	pq[j].index = j
}

func (pq *entryHeap) Push(x interface{}) {
	item := x.(*entry)
	item.index = len(*pq)
	*pq = append(*pq, item)
}

func (pq *entryHeap) Pop() interface{} {
	old := *pq
	n := len(old)
	item := old[n-1]
	item.index = -1
	*pq = old[:n-1]
	return item
}
