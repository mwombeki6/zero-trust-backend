import {
  Injectable,
  CanActivate,
  ExecutionContext,
  UnauthorizedException,
  Logger,
  SetMetadata,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { Request } from 'express';
import { UserService } from '../../users/users.service';
import { User } from '../../users/entities/user.entity';
import {
  JsonWebTokenError,
  NotBeforeError,
  TokenExpiredError,
} from 'jsonwebtoken';

// Extend Request interface to include user
interface AuthenticatedRequest extends Request {
  user: User;
}

// Define JWT payload interface
interface JwtPayload {
  sub: string;
  email: string;
  username: string;
  role: string;
  iat: number;
  exp?: number;
}

// Decorator to make routes public (skip JWT validation)
export const IS_PUBLIC_KEY = 'isPublic';
export const Public = () => SetMetadata(IS_PUBLIC_KEY, true);

@Injectable()
export class JwtAuthGuard implements CanActivate {
  private readonly logger = new Logger(JwtAuthGuard.name);

  constructor(
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
    private readonly userService: UserService,
    private readonly reflector: Reflector,
  ) {}

  async canActivate(context: ExecutionContext): Promise<boolean> {
    const isPublic = this.reflector.getAllAndOverride<boolean>(IS_PUBLIC_KEY, [
      context.getHandler(),
      context.getClass(),
    ]);

    if (isPublic) return true;

    const request = context.switchToHttp().getRequest<AuthenticatedRequest>();
    const token = this.extractTokenFromHeader(request);

    if (!token) {
      this.logger.warn('No token provided in request');
      throw new UnauthorizedException('Access token is required');
    }

    try {
      const payload = await this.jwtService.verifyAsync<JwtPayload>(token, {
        secret: this.configService.get<string>('JWT_SECRET'),
      });

      if (!payload?.sub) {
        this.logger.warn('Invalid token payload');
        throw new UnauthorizedException('Invalid token payload');
      }

      const user = await this.userService.findOne(payload.sub);

      if (!user) {
        this.logger.warn(`User not found for token: ${payload.sub}`);
        throw new UnauthorizedException('User not found');
      }

      if (!user.is_active) {
        this.logger.warn(`Inactive user attempted access: ${user.email}`);
        throw new UnauthorizedException('Account is deactivated');
      }

      const currentTime = Math.floor(Date.now() / 1000);
      if (
        (payload.iat && currentTime - payload.iat > this.getMaxTokenAge()) ||
        (payload.exp && payload.exp < currentTime)
      ) {
        this.logger.warn(`Expired token used by user: ${user.email}`);
        throw new UnauthorizedException('Token has expired');
      }

      request.user = user;
      this.logger.debug(`User authenticated: ${user.email} (${user.role})`);

      return true;
    } catch (err: unknown) {
      if (err instanceof UnauthorizedException) throw err;

      if (err instanceof JsonWebTokenError) {
        throw new UnauthorizedException('Invalid token format');
      }
      if (err instanceof TokenExpiredError) {
        throw new UnauthorizedException('Token has expired');
      }
      if (err instanceof NotBeforeError) {
        throw new UnauthorizedException('Token not yet valid');
      }

      this.logger.error(
        'Token validation failed',
        err instanceof Error ? err.message : String(err),
      );
      throw new UnauthorizedException('Token validation failed');
    }
  }

  /**
   * Extract JWT token from Authorization header
   */
  private extractTokenFromHeader(request: Request): string | undefined {
    const authHeader = request.headers.authorization;
    if (typeof authHeader !== 'string') return undefined;

    const parts = authHeader.trim().split(/\s+/);
    if (parts.length !== 2 || parts[0] !== 'Bearer') {
      this.logger.warn('Invalid authorization header format');
      return undefined;
    }

    return parts[1];
  }

  /**
   * Get maximum token age in seconds
   */
  private getMaxTokenAge(): number {
    const expiresIn = this.configService.get<string>(
      'JWT_ACCESS_EXPIRES_IN',
      '24h',
    );

    if (expiresIn.endsWith('h')) {
      return parseInt(expiresIn, 10) * 3600;
    }
    if (expiresIn.endsWith('m')) {
      return parseInt(expiresIn, 10) * 60;
    }
    if (expiresIn.endsWith('d')) {
      return parseInt(expiresIn, 10) * 86400;
    }
    if (expiresIn.endsWith('s')) {
      return parseInt(expiresIn, 10);
    }
    return 24 * 3600;
  }
}
