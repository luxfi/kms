// Copyright (C) 2026, Lux Partners Limited. All rights reserved.
// See the file LICENSE for licensing terms.

package metric

// Registerer is the minimal interface required to register and create metrics.
type Registerer interface {
	Metrics
	Register(Collector) error
	MustRegister(...Collector)
}

// Registry is a registerer that can also gather metric families.
type Registry interface {
	Registerer
	Gatherer
}

// WrapRegistererWithPrefix returns a Registerer that prefixes every
// registered metric's name with prefix before delegating to next.
// Mirrors prometheus/client_golang.WrapRegistererWithPrefix.
//
// The shim is intentionally minimal: it passes registrations through
// without rewriting names. Callers who want true prefixing should
// embed the prefix into the metric's Namespace/Subsystem at creation.
func WrapRegistererWithPrefix(prefix string, next Registerer) Registerer {
	return &prefixRegisterer{prefix: prefix, next: next}
}

// WrapRegistererWith returns a Registerer that attaches the given
// labels to every metric registered through it. Mirrors prometheus/
// client_golang.WrapRegistererWith. Like the prefix variant, the
// shim passes registrations through without rewriting labels —
// callers wanting true label-wrapping should embed via ConstLabels.
func WrapRegistererWith(_ Labels, next Registerer) Registerer {
	return next
}

type prefixRegisterer struct {
	prefix string
	next   Registerer
}

func (p *prefixRegisterer) Register(c Collector) error { return p.next.Register(c) }
func (p *prefixRegisterer) MustRegister(cs ...Collector) { p.next.MustRegister(cs...) }
func (p *prefixRegisterer) NewCounter(name, help string) Counter {
	return p.next.NewCounter(p.prefix+name, help)
}
func (p *prefixRegisterer) NewGauge(name, help string) Gauge {
	return p.next.NewGauge(p.prefix+name, help)
}
func (p *prefixRegisterer) NewHistogram(name, help string, buckets []float64) Histogram {
	return p.next.NewHistogram(p.prefix+name, help, buckets)
}
func (p *prefixRegisterer) NewSummary(name, help string, objectives map[float64]float64) Summary {
	return p.next.NewSummary(p.prefix+name, help, objectives)
}
func (p *prefixRegisterer) NewCounterVec(name, help string, labelNames []string) CounterVec {
	return p.next.NewCounterVec(p.prefix+name, help, labelNames)
}
func (p *prefixRegisterer) NewGaugeVec(name, help string, labelNames []string) GaugeVec {
	return p.next.NewGaugeVec(p.prefix+name, help, labelNames)
}
func (p *prefixRegisterer) NewHistogramVec(name, help string, labelNames []string, buckets []float64) HistogramVec {
	return p.next.NewHistogramVec(p.prefix+name, help, labelNames, buckets)
}
func (p *prefixRegisterer) NewSummaryVec(name, help string, labelNames []string, objectives map[float64]float64) SummaryVec {
	return p.next.NewSummaryVec(p.prefix+name, help, labelNames, objectives)
}
func (p *prefixRegisterer) Registry() Registry {
	if r, ok := p.next.(Registry); ok {
		return r
	}
	return nil
}
