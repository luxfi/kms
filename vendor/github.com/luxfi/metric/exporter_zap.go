// Copyright (C) 2019-2026, Lux Industries Inc. All rights reserved.
// See the file LICENSE for licensing terms.

// ZAP-native metric exporter — the default metric transport.
//
// Metric families serialize to JSON inside a luxfi/zap envelope and ship
// over TCP to a ZAP-aware o11y collector (hanzo/o11y has a matching
// receiver). Zero google.golang.org/protobuf, zero OTLP, zero gRPC.
//
// Wire layout per export call:
//
//	zap envelope, MsgType=MsgMetricBatch
//	└─ root object
//	   └─ FieldPayload (bytes): JSON-encoded MetricBatch
//
// MetricBatch carries app/resource attributes + a list of MetricFamily
// rows (same shape as the in-process gatherer.Gather() output).
//
// Mirrors luxfi/trace/exporter_zap.go (MsgSpanBatch=1). The two
// transports share the same ZAP node + collector endpoint by convention
// (the o11y collector binds :4317 and routes by MsgType in the envelope
// flags field).

package metric

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"math"
	"sync"
	"time"

	"github.com/luxfi/zap"
)

// MsgMetricBatch is the ZAP MsgType that carries a MetricBatch payload.
//
// Stable wire ID for the metric transport on the ZAP bus. Append-only —
// renumbering breaks every deployed collector in lockstep. Coordinates
// with luxfi/trace.MsgSpanBatch (=1); collectors switch on the
// MsgType-in-flags-upper-byte to route to the right ingest path.
const MsgMetricBatch uint16 = 2

// MetricBatch is the JSON shape that rides inside the ZAP envelope's
// payload field. One batch per Export call (typically one Gather()
// snapshot per scrape interval).
type MetricBatch struct {
	AppName     string            `json:"appName,omitempty"`
	Version     string            `json:"version,omitempty"`
	Resource    map[string]string `json:"resource,omitempty"`
	TimestampNs int64             `json:"timestampNs"`
	Families    []MetricFamilyWire `json:"families"`
}

// MetricFamilyWire is the JSON-stable wire shape of a MetricFamily.
// Mirrors metric.MetricFamily but pins the field names so the collector
// side can decode without depending on this package's Go types.
type MetricFamilyWire struct {
	Name    string       `json:"name"`
	Help    string       `json:"help,omitempty"`
	Type    string       `json:"type"`
	Metrics []MetricWire `json:"metrics"`
}

// MetricWire is the JSON-stable wire shape of a single Metric.
type MetricWire struct {
	Labels      map[string]string `json:"labels,omitempty"`
	Value       *float64          `json:"value,omitempty"`       // counter/gauge
	SampleCount *uint64           `json:"sampleCount,omitempty"` // histogram/summary
	SampleSum   *float64          `json:"sampleSum,omitempty"`   // histogram/summary
	Buckets     []BucketWire      `json:"buckets,omitempty"`     // histogram
	Quantiles   []QuantileWire    `json:"quantiles,omitempty"`   // summary
}

type BucketWire struct {
	UpperBound      float64 `json:"upperBound"`
	CumulativeCount uint64  `json:"cumulativeCount"`
}

type QuantileWire struct {
	Quantile float64 `json:"quantile"`
	Value    float64 `json:"value"`
}

// ZAPExporterConfig configures the ZAP-native exporter.
type ZAPExporterConfig struct {
	// Endpoint is the collector address (host:port). Defaults to
	// "127.0.0.1:4317" (the canonical o11y ZAP port).
	Endpoint string

	// AppName + Version land in every emitted batch's metadata.
	AppName string
	Version string

	// Resource attributes shipped with every batch (e.g., k8s namespace,
	// pod name, network ID).
	Resource map[string]string

	// Logger — defaults to slog.Default().
	Logger *slog.Logger
}

// ZAPExporter ships metric families over a luxfi/zap connection.
//
// Fire-and-forget by design: tracing and metrics MUST NEVER block the
// host process. Send failures invalidate the cached connection and
// trigger a reconnect on the next Export call; no batches are buffered
// in memory.
type ZAPExporter struct {
	cfg ZAPExporterConfig

	mu       sync.Mutex
	node     *zap.Node
	serverID string
	closed   bool
}

// NewZAPExporter constructs a metric exporter that ships over ZAP.
//
// Returns the exporter even if the initial connect fails — the next
// Export call will retry. This matches the trace exporter's posture:
// fire-and-forget means startup never fails on collector reachability.
func NewZAPExporter(cfg ZAPExporterConfig) (*ZAPExporter, error) {
	if cfg.Endpoint == "" {
		cfg.Endpoint = "127.0.0.1:4317"
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}

	node := zap.NewNode(zap.NodeConfig{
		NodeID:      fmt.Sprintf("metric-%s", cfg.AppName),
		ServiceType: "_o11y._tcp",
		Port:        0,
		Logger:      cfg.Logger,
		NoDiscovery: true,
	})
	if err := node.Start(); err != nil {
		return nil, fmt.Errorf("metric zap exporter start: %w", err)
	}

	e := &ZAPExporter{
		cfg:  cfg,
		node: node,
	}
	if err := e.connect(); err != nil {
		// Log and continue — exporter retries on first export.
		cfg.Logger.Debug("metric zap exporter: initial connect failed (will retry on export)",
			"endpoint", cfg.Endpoint, "err", err)
	}
	return e, nil
}

// connect dials the collector and caches the peer ID.
//
// Idempotent under the mutex — called from NewZAPExporter and from
// Export when an earlier connect failed.
func (e *ZAPExporter) connect() error {
	if err := e.node.ConnectDirect(e.cfg.Endpoint); err != nil {
		return err
	}
	peers := e.node.Peers()
	if len(peers) == 0 {
		return fmt.Errorf("metric zap exporter: connected but no peer ID for %s", e.cfg.Endpoint)
	}
	e.serverID = peers[0]
	return nil
}

// Export serializes families to JSON, wraps them in a ZAP envelope, and
// fires them over the cached connection. Fire-and-forget — no response
// is expected, no waiting on the collector.
func (e *ZAPExporter) Export(ctx context.Context, families []*MetricFamily) error {
	if len(families) == 0 {
		return nil
	}

	e.mu.Lock()
	defer e.mu.Unlock()

	if e.closed {
		return fmt.Errorf("metric zap exporter: shut down")
	}
	if e.serverID == "" {
		if err := e.connect(); err != nil {
			e.cfg.Logger.Debug("metric zap exporter: connect retry failed; dropping batch",
				"endpoint", e.cfg.Endpoint, "err", err)
			return nil
		}
	}

	batch := MetricBatch{
		AppName:     e.cfg.AppName,
		Version:     e.cfg.Version,
		Resource:    e.cfg.Resource,
		TimestampNs: time.Now().UnixNano(),
		Families:    make([]MetricFamilyWire, 0, len(families)),
	}
	for _, fam := range families {
		batch.Families = append(batch.Families, translateFamily(fam))
	}

	payload, err := json.Marshal(&batch)
	if err != nil {
		return fmt.Errorf("metric zap exporter: marshal batch: %w", err)
	}

	wire, err := encodeMetricBatch(payload)
	if err != nil {
		return err
	}
	msg, err := zap.Parse(wire)
	if err != nil {
		return fmt.Errorf("metric zap exporter: parse outgoing: %w", err)
	}

	if err := e.node.Send(ctx, e.serverID, msg); err != nil {
		// Connection died — invalidate and let the next call reconnect.
		e.serverID = ""
		e.cfg.Logger.Debug("metric zap exporter: send failed; will reconnect", "err", err)
		return nil
	}
	return nil
}

// ExportGatherer is the convenience entry point — calls Gather() on the
// supplied Gatherer and ships the resulting families. Use this when
// driving the exporter from a scrape loop.
func (e *ZAPExporter) ExportGatherer(ctx context.Context, g Gatherer) error {
	families, err := g.Gather()
	if err != nil {
		return fmt.Errorf("metric zap exporter: gather: %w", err)
	}
	return e.Export(ctx, families)
}

// Shutdown closes the ZAP node. Safe to call multiple times.
func (e *ZAPExporter) Shutdown(_ context.Context) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return nil
	}
	e.closed = true
	e.node.Stop()
	return nil
}

// translateFamily converts an in-process MetricFamily into the JSON
// wire shape. Maps MetricType → string label, label slices → maps, and
// only emits the value fields that match the metric type.
func translateFamily(fam *MetricFamily) MetricFamilyWire {
	out := MetricFamilyWire{
		Name:    fam.Name,
		Help:    fam.Help,
		Type:    fam.Type.String(),
		Metrics: make([]MetricWire, 0, len(fam.Metrics)),
	}
	for _, m := range fam.Metrics {
		mw := MetricWire{}
		if len(m.Labels) > 0 {
			mw.Labels = make(map[string]string, len(m.Labels))
			for _, lp := range m.Labels {
				mw.Labels[lp.Name] = lp.Value
			}
		}
		switch fam.Type {
		case MetricTypeCounter, MetricTypeGauge:
			v := m.Value.Value
			mw.Value = &v
		case MetricTypeHistogram:
			c := m.Value.SampleCount
			s := m.Value.SampleSum
			mw.SampleCount = &c
			mw.SampleSum = &s
			if len(m.Value.Buckets) > 0 {
				// Drop the trailing +Inf bucket. JSON can't represent
				// +Inf as a number and the +Inf bucket count is always
				// equal to SampleCount — it's already on the wire.
				mw.Buckets = make([]BucketWire, 0, len(m.Value.Buckets))
				for _, b := range m.Value.Buckets {
					if math.IsInf(b.UpperBound, +1) {
						continue
					}
					mw.Buckets = append(mw.Buckets, BucketWire{
						UpperBound:      b.UpperBound,
						CumulativeCount: b.CumulativeCount,
					})
				}
			}
		case MetricTypeSummary:
			c := m.Value.SampleCount
			s := m.Value.SampleSum
			mw.SampleCount = &c
			mw.SampleSum = &s
			if len(m.Value.Quantiles) > 0 {
				mw.Quantiles = make([]QuantileWire, len(m.Value.Quantiles))
				for i, q := range m.Value.Quantiles {
					mw.Quantiles[i] = QuantileWire{
						Quantile: q.Quantile,
						Value:    q.Value,
					}
				}
			}
		}
		out.Metrics = append(out.Metrics, mw)
	}
	return out
}

// encodeMetricBatch wraps a JSON payload in a ZAP envelope tagged
// MsgMetricBatch.
//
// Wire shape:
//
//	zap header (16) + root object { bytes payload @ offset 0 }
//
// MsgMetricBatch goes in the upper 8 bits of the ZAP flags field —
// same convention luxfi/trace uses for MsgSpanBatch.
func encodeMetricBatch(payload []byte) ([]byte, error) {
	const envelopeSize = 16
	b := zap.NewBuilder(envelopeSize + 64 + len(payload))
	root := b.StartObject(envelopeSize)
	root.SetBytes(0, payload)
	root.FinishAsRoot()
	return b.FinishWithFlags(MsgMetricBatch << 8), nil
}
