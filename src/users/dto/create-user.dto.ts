import {
  IsEmail,
  IsEnum,
  IsNotEmpty,
  IsOptional,
  IsString,
  MaxLength,
  MinLength,
} from 'class-validator';
import { UserRole } from '../entities/user.entity';

export class CreateUserDto {
  @IsString()
  @IsNotEmpty()
  @MaxLength(255)
  first_name: string;

  @IsString()
  @IsNotEmpty()
  @MaxLength(255)
  last_name: string;

  @IsString()
  @IsNotEmpty()
  @MaxLength(255)
  email: string;

  @IsString()
  @IsNotEmpty()
  @MaxLength(255)
  username: string;

  @IsString()
  @IsNotEmpty()
  @MaxLength(255)
  @MinLength(8)
  password: string;

  @IsEnum(UserRole)
  role: UserRole;
}

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
}
