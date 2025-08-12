import {
  IsEmail,
  IsString,
  IsNotEmpty,
  MinLength,
  MaxLength,
  IsOptional,
  IsBoolean,
  IsEnum,
  IsUUID
} from 'class-validator';
import { Transform } from 'class-transformer';
import { UserRole } from '../entities/user.entity';

// DTO for creating user (admin only)
export class CreateUserDto {
  @IsString()
  @IsNotEmpty()
  @MaxLength(255)
  first_name: string;

  @IsString()
  @IsNotEmpty()
  @MaxLength(255)
  last_name: string;

  @IsEmail()
  @IsNotEmpty()
  @MaxLength(255)
  email: string;

  @IsString()
  @IsNotEmpty()
  @MaxLength(255)
  username: string;

  @IsString()
  @IsNotEmpty()
  @MinLength(8)
  @MaxLength(255)
  password: string;

  @IsEnum(UserRole)
  role: UserRole;

  @IsOptional()
  @IsString()
  @MaxLength(1000)
  bio?: string;
}

// DTO for updating user profile (self-update)
export class UpdateUserDto {
  @IsOptional()
  @IsString()
  @IsNotEmpty()
  @MaxLength(255)
  first_name?: string;

  @IsOptional()
  @IsString()
  @IsNotEmpty()
  @MaxLength(255)
  last_name?: string;

  @IsOptional()
  @IsEmail()
  @IsNotEmpty()
  @MaxLength(255)
  email?: string;

  @IsOptional()
  @IsString()
  @IsNotEmpty()
  @MaxLength(255)
  username?: string;

  @IsOptional()
  @IsString()
  @MaxLength(1000)
  bio?: string;
}

// DTO for admin updating users
export class AdminUpdateUserDto {
  @IsOptional()
  @IsString()
  @IsNotEmpty()
  @MaxLength(255)
  first_name?: string;

  @IsOptional()
  @IsString()
  @IsNotEmpty()
  @MaxLength(255)
  last_name?: string;

  @IsOptional()
  @IsEmail()
  @IsNotEmpty()
  @MaxLength(255)
  email?: string;

  @IsOptional()
  @IsString()
  @IsNotEmpty()
  @MaxLength(255)
  username?: string;

  @IsOptional()
  @IsEnum(UserRole)
  role?: UserRole;

  @IsOptional()
  @IsString()
  @MaxLength(1000)
  bio?: string;

  @IsOptional()
  @IsBoolean()
  is_email_verified?: boolean;

  @IsOptional()
  @IsBoolean()
  is_active?: boolean;
}

// DTO for password updates (separate for security)
export class UpdatePasswordDto {
  @IsString()
  @IsNotEmpty()
  current_password: string;

  @IsString()
  @IsNotEmpty()
  @MinLength(8)
  @MaxLength(255)
  new_password: string;
}

// DTO for user response (excludes sensitive data)
export class UserResponseDto {
  id: string;
  first_name: string;
  last_name: string;
  full_name: string;
  email: string;
  username: string;
  role: UserRole;
  bio: string | null;
  is_email_verified: boolean;
  is_active: boolean;
  last_login: Date | null;
  created_at: Date;
  updated_at: Date;

  constructor(user: any) {
    this.id = user.id;
    this.first_name = user.first_name;
    this.last_name = user.last_name;
    this.full_name = user.full_name || `${user.first_name} ${user.last_name}`;
    this.email = user.email;
    this.username = user.username;
    this.role = user.role;
    this.bio = user.bio;
    this.is_email_verified = user.is_email_verified;
    this.is_active = user.is_active;
    this.last_login = user.last_login;
    this.created_at = user.created_at;
    this.updated_at = user.updated_at;
  }
}

// DTO for user list/search queries
export class UserListDto {
  @IsOptional()
  @Transform(({ value }) => parseInt(value))
  page?: number = 1;

  @IsOptional()
  @Transform(({ value }) => parseInt(value))
  limit?: number = 10;

  @IsOptional()
  @IsString()
  search?: string; // Search by name, email, username

  @IsOptional()
  @IsEnum(UserRole)
  role?: UserRole;

  @IsOptional()
  @IsBoolean()
  @Transform(({ value }) => value === 'true')
  is_active?: boolean;

  @IsOptional()
  @IsBoolean()
  @Transform(({ value }) => value === 'true')
  is_email_verified?: boolean;

  @IsOptional()
  @IsString()
  sortBy?: string = 'created_at'; // Field to sort by

  @IsOptional()
  @IsString()
  sortOrder?: 'ASC' | 'DESC' = 'DESC'; // Sort order
}

// DTO for user statistics (admin dashboard)
export class UserStatsResponseDto {
  total_users: number;
  active_users: number;
  verified_users: number;
  developers: number;
  admins: number;
  new_users_this_month: number;
  new_users_this_week: number;

  constructor(stats: Partial<UserStatsResponseDto>) {
    Object.assign(this, stats);
  }
}

// DTO for bulk user operations (admin)
export class BulkUserActionDto {
  @IsArray()
  @IsUUID(4, { each: true })
  user_ids: string[];

  @IsEnum(['activate', 'deactivate', 'verify_email', 'delete'])
  action: 'activate' | 'deactivate' | 'verify_email' | 'delete';
}

// Import IsArray decorator
import { IsArray } from 'class-validator';