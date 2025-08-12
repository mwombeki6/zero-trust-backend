import {
  Injectable,
  ConflictException,
  NotFoundException,
  BadRequestException,
  ForbiddenException
} from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository, FindOptionsWhere, ILike, Between } from 'typeorm';
import * as bcrypt from 'bcrypt';
import { User, UserRole } from './entities/user.entity';
import {
  CreateUserDto,
  UpdateUserDto,
  AdminUpdateUserDto,
  UpdatePasswordDto,
  UserResponseDto,
  UserListDto,
  UserStatsResponseDto,
  BulkUserActionDto
} from './dto/user.dto';

@Injectable()
export class UserService {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
  ) {}

  /**
   * Create a new user (Admin only)
   */
  async create(createUserDto: CreateUserDto): Promise<UserResponseDto> {
    await this.checkEmailExists(createUserDto.email);
    await this.checkUsernameExists(createUserDto.username);

    const hashedPassword = await this.hashPassword(createUserDto.password);

    const user = this.userRepository.create({
      ...createUserDto,
      password: hashedPassword,
    });

    const savedUser = await this.userRepository.save(user);
    return new UserResponseDto(savedUser);
  }

  /**
   * Find all users with pagination, filtering, and search
   */
  async findAll(userListDto: UserListDto) {
    const {
      page = 1,
      limit = 10,
      search,
      role,
      is_active,
      is_email_verified,
      sortBy = 'created_at',
      sortOrder = 'DESC'
    } = userListDto;

    const skip = (page - 1) * limit;
    const queryBuilder = this.userRepository.createQueryBuilder('user');

    // Apply filters
    if (role) {
      queryBuilder.andWhere('user.role = :role', { role });
    }
    if (is_active !== undefined) {
      queryBuilder.andWhere('user.is_active = :is_active', { is_active });
    }
    if (is_email_verified !== undefined) {
      queryBuilder.andWhere('user.is_email_verified = :is_email_verified', { is_email_verified });
    }

    // Apply search
    if (search) {
      queryBuilder.andWhere(
        '(user.first_name ILIKE :search OR user.last_name ILIKE :search OR user.email ILIKE :search OR user.username ILIKE :search)',
        { search: `%${search}%` }
      );
    }

    // Apply sorting
    const allowedSortFields = ['created_at', 'updated_at', 'first_name', 'last_name', 'email', 'username'];
    const sortField = allowedSortFields.includes(sortBy) ? sortBy : 'created_at';
    queryBuilder.orderBy(`user.${sortField}`, sortOrder);

    // Apply pagination
    queryBuilder.skip(skip).take(limit);

    const [users, total] = await queryBuilder.getManyAndCount();
    const userResponses = users.map(user => new UserResponseDto(user));

    return {
      data: userResponses,
      pagination: {
        page,
        limit,
        total,
        totalPages: Math.ceil(total / limit),
        hasNext: page < Math.ceil(total / limit),
        hasPrev: page > 1,
      },
    };
  }

  /**
   * Find user by ID
   */
  async findOne(id: string): Promise<UserResponseDto> {
    const user = await this.findUserById(id);
    return new UserResponseDto(user);
  }

  /**
   * Update user profile (self-update)
   */
  async update(id: string, updateUserDto: UpdateUserDto): Promise<UserResponseDto> {
    const user = await this.findUserById(id);

    // Check email uniqueness if being updated
    if (updateUserDto.email && updateUserDto.email !== user.email) {
      await this.checkEmailExists(updateUserDto.email, id);
    }

    // Check username uniqueness if being updated
    if (updateUserDto.username && updateUserDto.username !== user.username) {
      await this.checkUsernameExists(updateUserDto.username, id);
    }

    Object.assign(user, updateUserDto);
    const updatedUser = await this.userRepository.save(user);
    return new UserResponseDto(updatedUser);
  }

  /**
   * Admin update user (can modify more fields)
   */
  async adminUpdate(id: string, adminUpdateDto: AdminUpdateUserDto): Promise<UserResponseDto> {
    const user = await this.findUserById(id);

    // Check email uniqueness if being updated
    if (adminUpdateDto.email && adminUpdateDto.email !== user.email) {
      await this.checkEmailExists(adminUpdateDto.email, id);
    }

    // Check username uniqueness if being updated
    if (adminUpdateDto.username && adminUpdateDto.username !== user.username) {
      await this.checkUsernameExists(adminUpdateDto.username, id);
    }

    Object.assign(user, adminUpdateDto);
    const updatedUser = await this.userRepository.save(user);
    return new UserResponseDto(updatedUser);
  }

  /**
   * Update user password
   */
  async updatePassword(id: string, updatePasswordDto: UpdatePasswordDto): Promise<void> {
    const user = await this.findUserById(id);

    // Verify current password
    const isCurrentPasswordValid = await bcrypt.compare(updatePasswordDto.current_password, user.password);
    if (!isCurrentPasswordValid) {
      throw new BadRequestException('Current password is incorrect');
    }

    // Check if new password is different
    const isSamePassword = await bcrypt.compare(updatePasswordDto.new_password, user.password);
    if (isSamePassword) {
      throw new BadRequestException('New password must be different from current password');
    }

    // Hash and update password
    user.password = await this.hashPassword(updatePasswordDto.new_password);
    await this.userRepository.save(user);
  }

  /**
   * Soft delete user
   */
  async remove(id: string): Promise<void> {
    const user = await this.findUserById(id);
    user.is_active = false;
    await this.userRepository.save(user);
  }

  /**
   * Permanently delete user (Admin only)
   */
  async permanentDelete(id: string): Promise<void> {
    const user = await this.findUserById(id);
    await this.userRepository.remove(user);
  }

  /**
   * Get user statistics for admin dashboard
   */
  async getStats(): Promise<UserStatsResponseDto> {
    const now = new Date();
    const startOfMonth = new Date(now.getFullYear(), now.getMonth(), 1);
    const startOfWeek = new Date(now.setDate(now.getDate() - now.getDay()));

    const [
      totalUsers,
      activeUsers,
      verifiedUsers,
      developers,
      admins,
      newUsersThisMonth,
      newUsersThisWeek,
    ] = await Promise.all([
      this.userRepository.count(),
      this.userRepository.count({ where: { is_active: true } }),
      this.userRepository.count({ where: { is_email_verified: true } }),
      this.userRepository.count({ where: { role: UserRole.DEVELOPER } }),
      this.userRepository.count({ where: { role: UserRole.ADMIN } }),
      this.userRepository.count({ where: { created_at: Between(startOfMonth, new Date()) } }),
      this.userRepository.count({ where: { created_at: Between(startOfWeek, new Date()) } }),
    ]);

    return new UserStatsResponseDto({
      total_users: totalUsers,
      active_users: activeUsers,
      verified_users: verifiedUsers,
      developers,
      admins,
      new_users_this_month: newUsersThisMonth,
      new_users_this_week: newUsersThisWeek,
    });
  }

  /**
   * Bulk operations on users (Admin only)
   */
  async bulkAction(bulkActionDto: BulkUserActionDto): Promise<{ affected: number }> {
    const { user_ids, action } = bulkActionDto;

    let updateQuery: any = {};

    switch (action) {
      case 'activate':
        updateQuery = { is_active: true };
        break;
      case 'deactivate':
        updateQuery = { is_active: false };
        break;
      case 'verify_email':
        updateQuery = { is_email_verified: true };
        break;
      case 'delete':
        const result = await this.userRepository.delete(user_ids);
        return { affected: result.affected || 0 };
    }

    const result = await this.userRepository.update(user_ids, updateQuery);
    return { affected: result.affected || 0 };
  }

  /**
   * Find user by email (for auth module)
   */
  async findByEmail(email: string): Promise<User | null> {
    return this.userRepository.findOne({ where: { email } });
  }

  /**
   * Find user by username (for auth module)
   */
  async findByUsername(username: string): Promise<User | null> {
    return this.userRepository.findOne({ where: { username } });
  }

  /**
   * Update last login timestamp (for auth module)
   */
  async updateLastLogin(id: string): Promise<void> {
    await this.userRepository.update(id, { last_login: new Date() });
  }

  /**
   * Update email verification status (for auth module)
   */
  async markEmailAsVerified(id: string): Promise<void> {
    await this.userRepository.update(id, {
      is_email_verified: true,
      is_active: true,
      email_verification_token: null,
      email_verification_expires: null
    });
  }

  /**
   * Set email verification token (for auth module)
   */
  async setEmailVerificationToken(id: string, token: string, expires: Date): Promise<void> {
    await this.userRepository.update(id, {
      email_verification_token: token,
      email_verification_expires: expires
    });
  }

  /**
   * Set password reset token (for auth module)
   */
  async setPasswordResetToken(id: string, token: string, expires: Date): Promise<void> {
    await this.userRepository.update(id, {
      password_reset_token: token,
      password_reset_expires: expires
    });
  }

  /**
   * Reset password (for auth module)
   */
  async resetPassword(id: string, newPassword: string): Promise<void> {
    const hashedPassword = await this.hashPassword(newPassword);
    await this.userRepository.update(id, {
      password: hashedPassword,
      password_reset_token: null,
      password_reset_expires: null
    });
  }

  // Private helper methods
  private async findUserById(id: string): Promise<User> {
    const user = await this.userRepository.findOne({ where: { id } });
    if (!user) {
      throw new NotFoundException('User not found');
    }
    return user;
  }

  private async checkEmailExists(email: string, excludeId?: string): Promise<void> {
    const where: FindOptionsWhere<User> = { email };
    if (excludeId) {
      where.id = Not(excludeId);
    }

    const existingUser = await this.userRepository.findOne({ where });
    if (existingUser) {
      throw new ConflictException('Email already exists');
    }
  }

  private async checkUsernameExists(username: string, excludeId?: string): Promise<void> {
    const where: FindOptionsWhere<User> = { username };
    if (excludeId) {
      where.id = Not(excludeId);
    }

    const existingUser = await this.userRepository.findOne({ where });
    if (existingUser) {
      throw new ConflictException('Username already exists');
    }
  }

  private async hashPassword(password: string): Promise<string> {
    const saltRounds = 12;
    return bcrypt.hash(password, saltRounds);
  }
}

// Import Not operator
import { Not } from 'typeorm';