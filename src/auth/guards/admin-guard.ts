import {
  Injectable,
  CanActivate,
  ExecutionContext,
  ForbiddenException,
  UnauthorizedException,
  Logger,
  SetMetadata,
} from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { Request } from 'express';
import { User, UserRole } from '../../users/entities/user.entity';

// Extend Request interface to include user
interface AuthenticatedRequest extends Request {
  user: User;
}

// Decorator constants
export const ROLES_KEY = 'roles';
export const ADMIN_OR_OWNER_KEY = 'adminOrOwner';

// Decorators
export const Roles = (...roles: UserRole[]) => SetMetadata(ROLES_KEY, roles);
export const AdminOrOwner = () => SetMetadata(ADMIN_OR_OWNER_KEY, true);

@Injectable()
export class AdminGuard implements CanActivate {
  private readonly logger = new Logger(AdminGuard.name);

  constructor(private readonly reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const request = context.switchToHttp().getRequest<AuthenticatedRequest>();
    const user = request.user;

    // Check if user is attached to request (should be done by JwtAuthGuard)
    if (!user) {
      this.logger.warn(
        'No user found in request - JwtAuthGuard should run first',
      );
      throw new UnauthorizedException('Authentication required');
    }

    // Get required roles from decorator
    const requiredRoles = this.reflector.getAllAndOverride<UserRole[]>(
      ROLES_KEY,
      [context.getHandler(), context.getClass()],
    );

    // Get admin or owner requirement from decorator
    const adminOrOwner = this.reflector.getAllAndOverride<boolean>(
      ADMIN_OR_OWNER_KEY,
      [context.getHandler(), context.getClass()],
    );

    // If specific roles are required, check them
    if (requiredRoles && requiredRoles.length > 0) {
      return this.checkRoles(user, requiredRoles);
    }

    // If admin or owner is required, check for admin or resource ownership
    if (adminOrOwner) {
      return this.checkAdminOrOwner(request, user);
    }

    // Default behavior: require admin role
    return this.checkAdminRole(user);
  }

  /**
   * Check if user has admin role
   */
  private checkAdminRole(user: User): boolean {
    if (user.role !== UserRole.ADMIN) {
      this.logger.warn(
        `Access denied for user: ${user.email} (role: ${user.role}) - Admin required`,
      );
      throw new ForbiddenException(
        'Access denied. Administrator privileges required.',
      );
    }

    this.logger.debug(`Admin access granted to user: ${user.email}`);
    return true;
  }

  /**
   * Check if user has any of the required roles
   */
  private checkRoles(user: User, requiredRoles: UserRole[]): boolean {
    if (!requiredRoles.includes(user.role)) {
      this.logger.warn(
        `Access denied for user: ${user.email} (role: ${user.role}) - Required roles: ${requiredRoles.join(', ')}`,
      );
      throw new ForbiddenException(
        `Access denied. Required role(s): ${requiredRoles.join(', ')}`,
      );
    }

    this.logger.debug(
      `Role-based access granted to user: ${user.email} (role: ${user.role})`,
    );
    return true;
  }

  /**
   * Check if user is admin or owns the resource
   */
  private checkAdminOrOwner(
    request: AuthenticatedRequest,
    user: User,
  ): boolean {
    // If user is admin, grant access
    if (user.role === UserRole.ADMIN) {
      this.logger.debug(`Admin access granted to user: ${user.email}`);
      return true;
    }

    // Check if user is accessing their own resource
    const resourceUserId = this.extractResourceUserId(request);

    if (resourceUserId && resourceUserId === user.id) {
      this.logger.debug(
        `Owner access granted to user: ${user.email} for resource: ${resourceUserId}`,
      );
      return true;
    }

    this.logger.warn(
      `Access denied for user: ${user.email} - Not admin or owner of resource`,
    );
    throw new ForbiddenException(
      'Access denied. Administrator privileges or resource ownership required.',
    );
  }

  /**
   * Extract user ID from request parameters or body
   */
  private extractResourceUserId(request: AuthenticatedRequest): string | null {
    const extract = (source: unknown): string | null => {
      if (typeof source !== 'object' || source === null) {
        return null;
      }

      // Explicitly type source as a dictionary after narrowing
      const record = source as Record<string, unknown>;
      const id = record.userId ?? record.id;

      if (typeof id === 'string') return id.trim();
      if (typeof id === 'number') return String(id);
      return null;
    };

    return (
      extract(request.params) ||
      extract(request.query) ||
      extract(request.body) ||
      null
    );
  }
}

// Role-based guard for flexible role checking
@Injectable()
export class RolesGuard implements CanActivate {
  private readonly logger = new Logger(RolesGuard.name);

  constructor(private readonly reflector: Reflector) {}

  canActivate(context: ExecutionContext): boolean {
    const requiredRoles = this.reflector.getAllAndOverride<UserRole[]>(
      ROLES_KEY,
      [context.getHandler(), context.getClass()],
    );

    // If no roles are specified, allow access
    if (!requiredRoles || requiredRoles.length === 0) {
      return true;
    }

    const request = context.switchToHttp().getRequest<AuthenticatedRequest>();
    const user = request.user;

    if (!user) {
      this.logger.warn('No user found in request for role checking');
      throw new UnauthorizedException('Authentication required');
    }

    const hasRole = requiredRoles.includes(user.role);

    if (!hasRole) {
      this.logger.warn(
        `Access denied for user: ${user.email} (role: ${user.role}) - Required roles: ${requiredRoles.join(', ')}`,
      );
      throw new ForbiddenException(
        `Access denied. Required role(s): ${requiredRoles.join(', ')}`,
      );
    }

    this.logger.debug(
      `Role-based access granted to user: ${user.email} (role: ${user.role})`,
    );
    return true;
  }
}
