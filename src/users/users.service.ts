import {
  ConflictException,
  Injectable,
  NotFoundException,
  BadRequestException,
} from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, EntityManager } from 'typeorm';
import { User, UserRole } from './entities/user.entity';
import {
  CreateUserDto,
  UpdateUserDto,
  //UserListDto,
} from './dto/create-user.dto';

@Injectable()
export class UserService {
  private readonly saltRounds = 12;

  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
  ) {}

  /**
   * Create a new user
   */
  async create(userData: CreateUserDto): Promise<User> {
    // Validate required fields
    this.validateCreateUserData(userData);

    const sanitizedEmail = userData.email.toLowerCase().trim();
    const sanitizedUsername = userData.username.toLowerCase().trim();

    return await this.userRepository.manager.transaction(async (manager) => {
      // Check for existing email or username
      await this.checkUserUniqueness(
        manager,
        sanitizedEmail,
        sanitizedUsername,
      );

      // Hash password
      const hashedPassword = await bcrypt.hash(
        userData.password,
        this.saltRounds,
      );

      // Create user entity
      const user = manager.create(User, {
        first_name: userData.first_name.trim(),
        last_name: userData.last_name.trim(),
        email: sanitizedEmail,
        username: sanitizedUsername,
        password: hashedPassword,
        role: userData.role,
        is_active: true, // Auto-activate users
      });

      const savedUser = await manager.save(user);

      // Return user without password
      // eslint-disable-next-line @typescript-eslint/no-unused-vars
      const { password: _, ...userWithoutPassword } = savedUser;
      return userWithoutPassword as User;
    });
  }

  /**
   * Find user by email for authentication
   */
  async findByEmailForAuth(email: string): Promise<User | null> {
    if (!email?.trim()) return null;

    return await this.userRepository.findOne({
      where: { email: email.toLowerCase().trim() },
      select: [
        'id',
        'email',
        'password',
        'username',
        'first_name',
        'last_name',
        'role',
        'is_active',
        'is_email_verified',
      ],
    });
  }

  /**
   * Find user by ID (without password)
   */
  async findOne(id: string): Promise<User> {
    if (!id?.trim()) {
      throw new BadRequestException('User ID is required');
    }

    const user = await this.userRepository.findOne({
      where: { id },
      select: [
        'id',
        'first_name',
        'last_name',
        'email',
        'username',
        'role',
        'is_active',
        'is_email_verified',
        'last_login',
        'created_at',
        'updated_at',
      ],
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    return user;
  }

  /**
   * Update user's last login timestamp
   */
  async updateLastLogin(userId: string): Promise<void> {
    await this.userRepository.update(userId, {
      last_login: new Date(),
    });
  }

  /**
   * Validate user password
   */
  async validatePassword(
    plainPassword: string,
    hashedPassword: string,
  ): Promise<boolean> {
    if (!plainPassword || !hashedPassword) return false;
    return await bcrypt.compare(plainPassword, hashedPassword);
  }

  /**
   * Update user profile
   */
  async update(id: string, updateData: UpdateUserDto): Promise<User> {
    await this.findOne(id); // Verify user exists

    const updateFields: Partial<User> = {};

    // Handle basic fields
    if (updateData.first_name !== undefined) {
      updateFields.first_name = updateData.first_name.trim();
    }
    if (updateData.last_name !== undefined) {
      updateFields.last_name = updateData.last_name.trim();
    }

    // Handle email update with uniqueness check
    if (updateData.email !== undefined) {
      const sanitizedEmail = updateData.email.toLowerCase().trim();
      await this.checkEmailUniqueness(sanitizedEmail, id);
      updateFields.email = sanitizedEmail;
    }

    // Handle username update with uniqueness check
    if (updateData.username !== undefined) {
      const sanitizedUsername = updateData.username.toLowerCase().trim();
      await this.checkUsernameUniqueness(sanitizedUsername, id);
      updateFields.username = sanitizedUsername;
    }

    // Perform update if there are changes
    if (Object.keys(updateFields).length > 0) {
      await this.userRepository.update(id, updateFields);
    }

    return this.findOne(id);
  }

  /**
   * Change user password
   */
  async changePassword(
    id: string,
    currentPassword: string,
    newPassword: string,
  ): Promise<void> {
    if (!currentPassword?.trim() || !newPassword?.trim()) {
      throw new BadRequestException('Current and new passwords are required');
    }

    if (newPassword.length < 8) {
      throw new BadRequestException(
        'Password must be at least 8 characters long',
      );
    }

    // Get user with password
    const user = await this.userRepository.findOne({
      where: { id },
      select: ['id', 'password'],
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    // Verify current password
    const isCurrentPasswordValid = await this.validatePassword(
      currentPassword,
      user.password,
    );
    if (!isCurrentPasswordValid) {
      throw new BadRequestException('Current password is incorrect');
    }

    // Hash and update new password
    const hashedNewPassword = await bcrypt.hash(newPassword, this.saltRounds);
    await this.userRepository.update(id, { password: hashedNewPassword });
  }

  /**
   * Get user count by role (for dashboard stats)
   */
  async getUserStats() {
    const [total, active, admins, developers] = await Promise.all([
      this.userRepository.count(),
      this.userRepository.count({ where: { is_active: true } }),
      this.userRepository.count({ where: { role: UserRole.ADMIN } }),
      this.userRepository.count({ where: { role: UserRole.DEVELOPER } }),
    ]);

    return {
      total,
      active,
      inactive: total - active,
      admins,
      developers,
    };
  }

  /* -------------------- PRIVATE HELPER METHODS -------------------- */

  private validateCreateUserData(userData: CreateUserDto): void {
    const requiredFields: (keyof CreateUserDto)[] = [
      'email',
      'password',
      'first_name',
      'last_name',
      'username',
    ];

    for (const field of requiredFields) {
      const value = userData[field];
      if (!value || (typeof value === 'string' && !value.trim())) {
        throw new BadRequestException(`${field.replace('_', ' ')} is required`);
      }
    }

    if (userData.password.length < 8) {
      throw new BadRequestException(
        'Password must be at least 8 characters long',
      );
    }

    // Basic email validation
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(userData.email)) {
      throw new BadRequestException('Please provide a valid email address');
    }
  }

  private async checkUserUniqueness(
    manager: EntityManager,
    email: string,
    username: string,
  ): Promise<void> {
    const existingUser = await manager.findOne(User, {
      where: [{ email }, { username }],
      select: ['email', 'username'],
    });

    if (existingUser) {
      if (existingUser.email === email) {
        throw new ConflictException(
          'An account with this email already exists',
        );
      }
      if (existingUser.username === username) {
        throw new ConflictException('This username is already taken');
      }
    }
  }

  private async checkEmailUniqueness(
    email: string,
    excludeUserId?: string,
  ): Promise<void> {
    const existingUser = await this.userRepository.findOne({
      where: { email },
      select: ['id'],
    });

    if (existingUser && existingUser.id !== excludeUserId) {
      throw new ConflictException('An account with this email already exists');
    }
  }

  private async checkUsernameUniqueness(
    username: string,
    excludeUserId?: string,
  ): Promise<void> {
    const existingUser = await this.userRepository.findOne({
      where: { username },
      select: ['id'],
    });

    if (existingUser && existingUser.id !== excludeUserId) {
      throw new ConflictException('This username is already taken');
    }
  }
}
