import {
  CanActivate,
  ExecutionContext,
  Injectable,
  Logger,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { Observable } from 'rxjs';
import { Request } from 'express';

@Injectable()
export class AuthGuard implements CanActivate {
  private readonly logger = new Logger(AuthGuard.name);

  constructor(private jwtService: JwtService) {}

  canActivate(
    context: ExecutionContext,
  ): boolean | Promise<boolean> | Observable<boolean> {
    const request = context.switchToHttp().getRequest<Request>();
    const token = this.extractTokenFromHeader(request);

    if (!token) {
      this.logger.error('Token not found in the Authorization header');
      throw new UnauthorizedException('Invalid token');
    }

    try {
      this.logger.log(`Token received: ${token}`);
      const payload = this.jwtService.verify(token);
      this.logger.log(
        `Token verified successfully. Payload: ${JSON.stringify(payload)}`,
      );
      request.userId = payload.userId;
    } catch (e) {
      this.logger.error(`Token verification failed: ${e.message}`);
      throw new UnauthorizedException('Invalid token');
    }
    return true;
  }

  private extractTokenFromHeader(request: Request): string | undefined {
    const authorization = request.headers.authorization;
    if (!authorization) {
      this.logger.error('Authorization header is missing');
      return undefined;
    }
    return authorization.split(' ')[1];
  }
}
