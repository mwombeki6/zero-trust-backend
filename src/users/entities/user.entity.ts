import {
  Column,
  CreateDateColumn,
  Entity,
  PrimaryGeneratedColumn,
  UpdateDateColumn,
} from 'typeorm';

// Enum for user roles
export enum UserRole {
  ADMIN = 'admin',
  DEVELOPER = 'developer',
}

@Entity()
export class User {
  @PrimaryGeneratedColumn('uuid')
  public id: string;

  @Column({ type: 'varchar', length: 255, nullable: false })
  first_name: string;

  @Column({ type: 'varchar', length: 255, nullable: false })
  last_name: string;

  @Column({ type: 'varchar', length: 255, nullable: false, unique: true })
  email: string;

  @Column({ type: 'varchar', length: 255, nullable: false, unique: true })
  username: string;

  @Column({ type: 'varchar', length: 255, nullable: false })
  password: string;

  @Column({ type: 'enum', enum: UserRole, default: UserRole.DEVELOPER })
  role: UserRole;

  @Column({ type: 'boolean', default: false })
  is_email_verified: boolean;

  @Column({ type: 'boolean', default: false })
  is_active: boolean; // allow login only if is_active = True

  @Column({ type: 'timestamp', nullable: true })
  last_login: Date | null;

  @Column({ type: 'varchar', length: 255, nullable: true })
  email_verification_token: string | null;

  @Column({ type: 'timestamp', nullable: true })
  email_verification_expires: Date | null;

  @Column({ type: 'varchar', length: 255, nullable: true })
  password_reset_token: string | null;

  @Column({ type: 'timestamp', nullable: true })
  password_reset_expires: Date | null;

  @CreateDateColumn({ type: 'timestamp' })
  created_at: Date;

  @UpdateDateColumn({ type: 'timestamp' })
  updated_at: Date;

  // Virtual properties for full name
  get full_name(): string {
    return `${this.first_name} ${this.last_name}`;
  }

  // Method for checking if user is admin
  isAdmin(): boolean {
    return this.role === UserRole.ADMIN;
  }

  // Method for checking if user is Developer
  isDeveloper(): boolean {
    return this.role === UserRole.DEVELOPER;
  }

  // Method to check if email verification expired
  isEmailVerificationExpired(): boolean {
    if (!this.email_verification_expires) return true;
    return new Date() > this.email_verification_expires;
  }

  // Method to check if password reset is expired
  isPasswordResetExpired(): boolean {
    if (!this.password_reset_expires) return true;
    return new Date() > this.password_reset_expires;
  }
}
