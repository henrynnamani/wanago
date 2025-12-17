import { NodeSDK } from '@opentelemetry/sdk-node';
import { getNodeAutoInstrumentations } from '@opentelemetry/auto-instrumentations-node';
import { OTLPTraceExporter } from '@opentelemetry/exporter-trace-otlp-grpc';
import {
  PeriodicExportingMetricReader,
  ConsoleMetricExporter,
} from '@opentelemetry/sdk-metrics';

const traceExporter = new OTLPTraceExporter({
  url: 'http://localhost:4317',
});

const metricReader = new PeriodicExportingMetricReader({
  exporter: new ConsoleMetricExporter(),
  exportIntervalMillis: 15000,
});

const sdk = new NodeSDK({
  serviceName: 'nestjs-opentelemetry-demo',
  traceExporter,
  metricReader,
  instrumentations: [getNodeAutoInstrumentations()],
});

(async () => {
  await sdk.start();
  console.log('✅ OpenTelemetry tracing & metrics initialized');
})();

process.on('SIGTERM', async () => {
  await sdk.shutdown();
  console.log('🛑 OpenTelemetry shutdown complete');
  process.exit(0);
});
