import {
  CallHandler,
  ExecutionContext,
  Injectable,
  NestInterceptor,
  Logger,
} from '@nestjs/common';
import { Observable, tap } from 'rxjs';
import { metrics } from '@opentelemetry/api';

const meter = metrics.getMeter('nestjs-meter');
const requestCount = meter.createCounter('http_requests_total', {
  description: 'Count of all HTTP requests',
});

@Injectable()
export class ObservabilityInterceptor implements NestInterceptor {
  private readonly logger = new Logger('HTTP');

  intercept(context: ExecutionContext, next: CallHandler): Observable<any> {
    const req = context.switchToHttp().getRequest();
    const method = req.method;
    const route = req.url;
    const now = Date.now();

    return next.handle().pipe(
      tap(() => {
        const duration = Date.now() - now;
        this.logger.log(`${method} ${route} - ${duration}ms`);

        requestCount.add(1, {
          method,
          route,
        });
      }),
    );
  }
}
