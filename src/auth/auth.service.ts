import {
  Injectable,
  BadRequestException,
  UnauthorizedException,
  ConflictException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import { UserService } from '../users/users.service';
import { User, UserRole } from '../users/entities/user.entity';
import { RegisterDto } from './dto/create-auth.dto';
import { LoginDto } from '../users/dto/create-user.dto';
import { AuthResponse } from '../users/interfaces/interafce';

// Define JWT payload interface
interface JwtPayload {
  sub: string;
  email: string;
  username: string;
  role: UserRole;
  iat: number;
}

@Injectable()
export class AuthService {
  constructor(
    private readonly userService: UserService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {}

  /**
   * Register a new user
   */
  async register(registerDto: RegisterDto): Promise<AuthResponse> {
    this.validateRegisterDto(registerDto);

    try {
      const userData = {
        ...registerDto,
        role: registerDto.role || UserRole.DEVELOPER,
      };

      const user = await this.userService.create(userData);
      await this.userService.updateLastLogin(user.id);

      return this.buildAuthResponse(user);
    } catch (error) {
      if (
        error instanceof ConflictException ||
        error instanceof BadRequestException
      ) {
        throw error;
      }
      console.error('Registration error:', error);
      throw new BadRequestException('Registration failed. Please try again.');
    }
  }

  /**
   * Create admin user (for initial setup or admin creation)
   */
  async createAdmin(registerDto: RegisterDto): Promise<AuthResponse> {
    this.validateRegisterDto(registerDto);

    try {
      const adminData = {
        ...registerDto,
        role: UserRole.ADMIN,
      };

      const user = await this.userService.create(adminData);
      await this.userService.updateLastLogin(user.id);

      return this.buildAuthResponse(user);
    } catch (error) {
      if (
        error instanceof ConflictException ||
        error instanceof BadRequestException
      ) {
        throw error;
      }
      console.error('Admin creation error:', error);
      throw new BadRequestException('Admin creation failed. Please try again.');
    }
  }

  /**
   * User login
   */
  async login(loginDto: LoginDto): Promise<AuthResponse> {
    this.validateLoginDto(loginDto);

    // Find user with password for authentication
    const user = await this.userService.findByEmailForAuth(loginDto.email);

    if (!user) {
      throw new UnauthorizedException('Invalid email or password');
    }

    // Check if account is active
    if (!user.is_active) {
      throw new UnauthorizedException(
        'Your account has been deactivated. Please contact support.',
      );
    }

    // Validate password
    const isPasswordValid = await this.userService.validatePassword(
      loginDto.password,
      user.password,
    );

    if (!isPasswordValid) {
      throw new UnauthorizedException('Invalid email or password');
    }

    // Update last login
    await this.userService.updateLastLogin(user.id);

    // Remove password from user object before building response
    // eslint-disable-next-line @typescript-eslint/no-unused-vars
    const { password: _, ...userWithoutPassword } = user;

    return this.buildAuthResponse(user);
  }

  /**
   * Get user profile (for dashboard)
   */
  async getProfile(userId: string): Promise<User> {
    return await this.userService.findOne(userId);
  }

  /**
   * Validate JWT token and return user
   */
  async validateToken(token: string): Promise<User> {
    try {
      const payload = await this.jwtService.verifyAsync<JwtPayload>(token, {
        secret: this.configService.get<string>('JWT_SECRET'),
      });

      const user = await this.userService.findOne(payload.sub);

      if (!user.is_active) {
        throw new UnauthorizedException('Account is deactivated');
      }

      return user;
    } catch (error) {
      console.error('Token validation error:', error);
      throw new UnauthorizedException('Invalid or expired token');
    }
  }

  /**
   * Change password (for authenticated users)
   */
  async changePassword(
    userId: string,
    currentPassword: string,
    newPassword: string,
  ): Promise<{ message: string }> {
    await this.userService.changePassword(userId, currentPassword, newPassword);
    return { message: 'Password changed successfully' };
  }

  /* -------------------- PRIVATE HELPER METHODS -------------------- */

  private async buildAuthResponse(user: User): Promise<AuthResponse> {
    const accessToken = await this.generateAccessToken(user);

    return {
      user: this.sanitizeUserForResponse(user),
      accessToken,
      expiresIn: this.getTokenExpirationTime(),
      dashboardUrl: this.getDashboardUrl(user.role),
    };
  }

  private async generateAccessToken(user: User): Promise<string> {
    const payload: JwtPayload = {
      sub: user.id,
      email: user.email,
      username: user.username,
      role: user.role,
      iat: Math.floor(Date.now() / 1000),
    };

    return this.jwtService.signAsync(payload, {
      secret: this.configService.get<string>('JWT_SECRET'),
      expiresIn: this.configService.get<string>('JWT_ACCESS_EXPIRES_IN', '24h'),
    });
  }

  private getTokenExpirationTime(): number {
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

  private getDashboardUrl(role: UserRole): string {
    switch (role) {
      case UserRole.ADMIN:
        return '/admin/dashboard';
      case UserRole.DEVELOPER:
        return '/developer/dashboard';
      default:
        return '/dashboard';
    }
  }

  private sanitizeUserForResponse(user: User) {
    // Remove sensitive fields from user object
    const {
      password,
      email_verification_token,
      password_reset_token,
      email_verification_expires,
      password_reset_expires,
      ...sanitizedUser
    } = user;

    // Suppress ESLint warnings for unused variables
    void password;
    void email_verification_token;
    void password_reset_token;
    void email_verification_expires;
    void password_reset_expires;

    return {
      ...sanitizedUser,
      full_name: `${user.first_name} ${user.last_name}`,
    };
  }

  private validateRegisterDto(registerDto: RegisterDto): void {
    const requiredFields: Array<{ key: keyof RegisterDto; name: string }> = [
      { key: 'email', name: 'Email' },
      { key: 'password', name: 'Password' },
      { key: 'first_name', name: 'First name' },
      { key: 'last_name', name: 'Last name' },
      { key: 'username', name: 'Username' },
    ];

    // Check required fields
    for (const field of requiredFields) {
      const value = registerDto[field.key];
      if (!value || (typeof value === 'string' && !value.trim())) {
        throw new BadRequestException(`${field.name} is required`);
      }
    }

    // Password strength validation
    if (registerDto.password.length < 8) {
      throw new BadRequestException(
        'Password must be at least 8 characters long',
      );
    }

    // Email format validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(registerDto.email)) {
      throw new BadRequestException('Please provide a valid email address');
    }

    // Username validation (no spaces, minimum length)
    if (registerDto.username.includes(' ')) {
      throw new BadRequestException('Username cannot contain spaces');
    }

    if (registerDto.username.length < 3) {
      throw new BadRequestException(
        'Username must be at least 3 characters long',
      );
    }
  }

  private validateLoginDto(loginDto: LoginDto): void {
    if (!loginDto.email?.trim()) {
      throw new BadRequestException('Email is required');
    }

    if (!loginDto.password?.trim()) {
      throw new BadRequestException('Password is required');
    }
  }
}
