// interfaces/auth-response.interface.ts

import { UserRole } from '../entities/user.entity';

export interface AuthResponse {
  user: {
    id: string;
    first_name: string;
    last_name: string;
    full_name: string;
    email: string;
    username: string;
    role: UserRole;
    is_active: boolean;
    is_email_verified: boolean;
    last_login: Date | null;
    created_at: Date;
    updated_at: Date;
  };
  accessToken: string;
  expiresIn: number;
  dashboardUrl: string;
}

export interface LoginResponse extends AuthResponse {
  message: string;
}

export interface RegisterResponse extends AuthResponse {
  message: string;
}