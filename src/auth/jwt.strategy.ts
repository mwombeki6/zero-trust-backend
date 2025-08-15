import { Injectable, UnauthorizedException } from '@nestjs/common';
import { PassportStrategy } from '@nestjs/passport';
import { ExtractJwt, Strategy } from 'passport-jwt';
import { ConfigService } from '@nestjs/config';
import { UserService } from '../users/users.service';
import { User, UserRole } from '../users/entities/user.entity';

// Define JWT payload interface to match your auth service
interface JwtPayload {
  sub: string;
  email: string;
  username: string;
  role: UserRole;
  iat: number;
}

@Injectable()
export class JwtStrategy extends PassportStrategy(Strategy) {
  constructor(
    private readonly configService: ConfigService,
    private readonly userService: UserService,
  ) {
    const jwtSecret = configService.get<string>('JWT_SECRET');

    if (!jwtSecret) {
      throw new Error('JWT_SECRET is not configured in environment variables');
    }

    super({
      jwtFromRequest: ExtractJwt.fromAuthHeaderAsBearerToken(),
      ignoreExpiration: false,
      secretOrKey: jwtSecret,
      algorithms: ['HS256'],
    });
  }

  /**
   * Validate JWT payload and return user object
   * This method is called automatically by Passport after JWT verification
   */
  async validate(payload: JwtPayload): Promise<User> {
    // Validate payload structure
    if (!payload || !payload.sub) {
      throw new UnauthorizedException('Invalid token payload');
    }

    try {
      // Get user from database using the service method that matches your auth service
      const user = await this.userService.findOne(payload.sub);

      if (!user) {
        throw new UnauthorizedException('User not found');
      }

      // Check if user account is still active
      if (!user.is_active) {
        throw new UnauthorizedException('Account is deactivated');
      }

      // Optional: Add additional security checks
      // Check if token is too old (additional security layer)
      if (payload.iat) {
        const tokenAge = Date.now() / 1000 - payload.iat;
        const maxAge = this.getMaxTokenAge();

        if (tokenAge > maxAge) {
          throw new UnauthorizedException('Token too old, please login again');
        }
      }

      // Return the full user object
      // Passport will attach this to request.user
      return user;
    } catch (error) {
      if (error instanceof UnauthorizedException) {
        throw error;
      }

      // Log the error for debugging
      console.error('JWT Strategy validation error:', error);
      throw new UnauthorizedException('Token validation failed');
    }
  }

  /**
   * Get maximum token age in seconds (matching auth service logic)
   */
  private getMaxTokenAge(): number {
    const expiresIn = this.configService.get<string>(
      'JWT_ACCESS_EXPIRES_IN',
      '24h',
    );

    // Convert time string to seconds
    if (expiresIn.endsWith('h')) {
      return parseInt(expiresIn) * 3600;
    } else if (expiresIn.endsWith('m')) {
      return parseInt(expiresIn) * 60;
    } else if (expiresIn.endsWith('d')) {
      return parseInt(expiresIn) * 86400;
    } else if (expiresIn.endsWith('s')) {
      return parseInt(expiresIn);
    }

    // Default to 24 hours
    return 24 * 3600;
  }
}
