// Package telemetry wires OpenTelemetry traces and metrics into the Gin
// middleware stack. In v1 it exports via OTLP/HTTP when GH_PROXY_OTEL_EXPORTER
// is set; otherwise it installs no-op providers so the rest of the stack can
// annotate spans/metrics unconditionally.
package telemetry

import (
	"context"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
)

// Providers bundles the OTel SDK handles so callers can shut them down.
type Providers struct {
	Tracer       trace.Tracer
	Meter        metric.Meter
	shutdownFns  []func(context.Context) error
	RequestCount metric.Int64Counter
	RequestDur   metric.Float64Histogram
}

// Setup initializes OTel. If endpoint is empty, no-op providers are installed.
func Setup(ctx context.Context, endpoint, serviceName string) (*Providers, error) {
	p := &Providers{}

	if endpoint == "" {
		p.Tracer = otel.Tracer(serviceName)
		p.Meter = otel.Meter(serviceName)
	} else {
		res, err := resource.New(ctx,
			resource.WithAttributes(semconv.ServiceName(serviceName)),
		)
		if err != nil {
			return nil, err
		}
		texp, err := otlptracehttp.New(ctx, otlptracehttp.WithEndpoint(endpoint), otlptracehttp.WithInsecure())
		if err != nil {
			return nil, err
		}
		tp := sdktrace.NewTracerProvider(
			sdktrace.WithBatcher(texp),
			sdktrace.WithResource(res),
		)
		otel.SetTracerProvider(tp)
		p.shutdownFns = append(p.shutdownFns, tp.Shutdown)

		mexp, err := otlpmetrichttp.New(ctx, otlpmetrichttp.WithEndpoint(endpoint), otlpmetrichttp.WithInsecure())
		if err != nil {
			return nil, err
		}
		mp := sdkmetric.NewMeterProvider(
			sdkmetric.WithReader(sdkmetric.NewPeriodicReader(mexp)),
			sdkmetric.WithResource(res),
		)
		otel.SetMeterProvider(mp)
		p.shutdownFns = append(p.shutdownFns, mp.Shutdown)

		p.Tracer = tp.Tracer(serviceName)
		p.Meter = mp.Meter(serviceName)
	}

	var err error
	p.RequestCount, err = p.Meter.Int64Counter("ghproxy.requests")
	if err != nil {
		return nil, err
	}
	p.RequestDur, err = p.Meter.Float64Histogram("ghproxy.request.duration_ms")
	if err != nil {
		return nil, err
	}
	return p, nil
}

// Shutdown flushes exporters.
func (p *Providers) Shutdown(ctx context.Context) error {
	for _, fn := range p.shutdownFns {
		if err := fn(ctx); err != nil {
			return err
		}
	}
	return nil
}

// Middleware returns a Gin handler that creates a span per request and emits
// the request counter/histogram. Request-scoped labels like tenant/repo/
// endpoint class are attached by downstream handlers via AnnotateRequest.
func (p *Providers) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		ctx, span := p.Tracer.Start(c.Request.Context(), c.FullPath(),
			trace.WithAttributes(
				attribute.String("http.method", c.Request.Method),
				attribute.String("http.route", c.FullPath()),
			),
		)
		c.Request = c.Request.WithContext(ctx)

		c.Next()

		status := c.Writer.Status()
		span.SetAttributes(attribute.Int("http.status_code", status))
		span.End()

		attrs := []attribute.KeyValue{
			attribute.String("route", c.FullPath()),
			attribute.String("method", c.Request.Method),
			attribute.String("status", strconv.Itoa(status)),
		}
		if t, ok := c.Get("tenant"); ok {
			attrs = append(attrs, attribute.String("tenant", t.(string)))
		}
		if r, ok := c.Get("repo"); ok {
			attrs = append(attrs, attribute.String("repo", r.(string)))
		}
		if e, ok := c.Get("endpoint_class"); ok {
			attrs = append(attrs, attribute.String("endpoint_class", e.(string)))
		}
		p.RequestCount.Add(ctx, 1, metric.WithAttributes(attrs...))
		p.RequestDur.Record(ctx, float64(time.Since(start).Milliseconds()), metric.WithAttributes(attrs...))
	}
}
