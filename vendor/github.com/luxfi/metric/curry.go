// Copyright (C) 2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

package metric

// Currying support for the *Vec families. Mirrors prometheus/client_golang's
// MetricVec.MustCurryWith: it binds a subset of label values up front and
// returns a vec that only needs the remaining labels. Implemented natively —
// the returned vec delegates to the base vec with the fixed labels merged in,
// so children are still created and registered on the base registry exactly
// once per full label set.

// mergeLabels returns a new Labels with b overlaid on a.
func mergeLabels(a, b Labels) Labels {
	out := make(Labels, len(a)+len(b))
	for k, v := range a {
		out[k] = v
	}
	for k, v := range b {
		out[k] = v
	}
	return out
}

// curryRemaining returns the label names from all that are not fixed, in
// declared order — these are the names WithLabelValues maps positionally.
func curryRemaining(all []string, fixed Labels) []string {
	rem := make([]string, 0, len(all))
	for _, n := range all {
		if _, ok := fixed[n]; !ok {
			rem = append(rem, n)
		}
	}
	return rem
}

// --- counter ---

func (v *counterVec) MustCurryWith(labels Labels) CounterVec {
	return &curriedCounterVec{base: v, fixed: cloneLabels(labels), remaining: curryRemaining(v.labelNames, labels)}
}

type curriedCounterVec struct {
	base      *counterVec
	fixed     Labels
	remaining []string
}

func (c *curriedCounterVec) With(labels Labels) Counter {
	return c.base.With(mergeLabels(c.fixed, labels))
}
func (c *curriedCounterVec) WithLabelValues(values ...string) Counter {
	return c.base.With(mergeLabels(c.fixed, labelsFromValues(c.remaining, values)))
}
func (c *curriedCounterVec) MustCurryWith(labels Labels) CounterVec {
	return c.base.MustCurryWith(mergeLabels(c.fixed, labels))
}
func (c *curriedCounterVec) Reset() { c.base.Reset() }

// --- gauge ---

func (v *gaugeVec) MustCurryWith(labels Labels) GaugeVec {
	return &curriedGaugeVec{base: v, fixed: cloneLabels(labels), remaining: curryRemaining(v.labelNames, labels)}
}

type curriedGaugeVec struct {
	base      *gaugeVec
	fixed     Labels
	remaining []string
}

func (c *curriedGaugeVec) With(labels Labels) Gauge {
	return c.base.With(mergeLabels(c.fixed, labels))
}
func (c *curriedGaugeVec) WithLabelValues(values ...string) Gauge {
	return c.base.With(mergeLabels(c.fixed, labelsFromValues(c.remaining, values)))
}
func (c *curriedGaugeVec) MustCurryWith(labels Labels) GaugeVec {
	return c.base.MustCurryWith(mergeLabels(c.fixed, labels))
}
func (c *curriedGaugeVec) Reset() { c.base.Reset() }

// --- histogram ---

func (v *histogramVec) MustCurryWith(labels Labels) HistogramVec {
	return &curriedHistogramVec{base: v, fixed: cloneLabels(labels), remaining: curryRemaining(v.labelNames, labels)}
}

type curriedHistogramVec struct {
	base      *histogramVec
	fixed     Labels
	remaining []string
}

func (c *curriedHistogramVec) With(labels Labels) Histogram {
	return c.base.With(mergeLabels(c.fixed, labels))
}
func (c *curriedHistogramVec) WithLabelValues(values ...string) Histogram {
	return c.base.With(mergeLabels(c.fixed, labelsFromValues(c.remaining, values)))
}
func (c *curriedHistogramVec) MustCurryWith(labels Labels) HistogramVec {
	return c.base.MustCurryWith(mergeLabels(c.fixed, labels))
}
func (c *curriedHistogramVec) Reset() { c.base.Reset() }

// --- summary ---

func (v *summaryVec) MustCurryWith(labels Labels) SummaryVec {
	return &curriedSummaryVec{base: v, fixed: cloneLabels(labels), remaining: curryRemaining(v.labelNames, labels)}
}

type curriedSummaryVec struct {
	base      *summaryVec
	fixed     Labels
	remaining []string
}

func (c *curriedSummaryVec) With(labels Labels) Summary {
	return c.base.With(mergeLabels(c.fixed, labels))
}
func (c *curriedSummaryVec) WithLabelValues(values ...string) Summary {
	return c.base.With(mergeLabels(c.fixed, labelsFromValues(c.remaining, values)))
}
func (c *curriedSummaryVec) MustCurryWith(labels Labels) SummaryVec {
	return c.base.MustCurryWith(mergeLabels(c.fixed, labels))
}
func (c *curriedSummaryVec) Reset() { c.base.Reset() }
