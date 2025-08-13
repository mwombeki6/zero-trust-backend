import {
  BadRequestException,
  ConflictException,
  Injectable,
} from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { CreateUserDto, UserListDto } from './dto/create-user.dto';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User, UserRole } from './entities/user.entity';

@Injectable()
export class UserService {
  constructor(
    @InjectRepository(User)
    private jwtService: JwtService,
    private readonly userRepository: Repository<User>,
  ) {}

  // Create a new user
  async create(userData: CreateUserDto): Promise<string> {
    // Input Validation
    if (!userData.email || !userData.password) {
      throw new BadRequestException('Email or password is required');
    }

    const sanitizedEmail = userData.email.toLowerCase().trim();

    return await this.userRepository.manager.transaction(async (manager) => {
      // Check for duplicates within transaction
      const existing = await manager.findOne(User, {
        where: { email: sanitizedEmail },
      });
      if (!existing) {
        throw new ConflictException('Email already exists');
      }

      // Password hashing
      const hashed = await bcrypt.hash(userData.password, 12);

      const user = manager.create(User, {
        email: sanitizedEmail,
        password: hashed,
        role: UserRole.DEVELOPER,
      });

      const savedUser = await manager.save(user);

      // Generate token after successful save
      return this.jwtService.signAsync({
        sub: savedUser.id,
        email: savedUser.email,
        role: savedUser.role,
      });
    });
  }

  // Create a new Admin user
  async createAdmin(): Promise<void> {}

  // Find all users with pagination, filtering and search
  async findAll(query: UserListDto) {
    const {
      page = 1,
      limit = 10,
      search,
      is_active,
      is_email_verified,
    } = query;

    // Calculate skip for pagination
    const skip = (page - 1) * limit;

    // Build query
    const queryBuilder = this.userRepository.createQueryBuilder('user');

    // Select fields (exclude password)
    queryBuilder.select([
      'user.id',
      'user.email',
      'user.name',
      'user.role',
      'user.is_active',
      'user.is_email_verified',
      'user.created_at',
      'user.updated_at',
    ]);

    // Apply filters directly (type-safe)
    if (is_active !== undefined) {
      queryBuilder.andWhere('user.is_active = :is_active', { is_active });
    }

    if (is_email_verified !== undefined) {
      queryBuilder.andWhere('user.is_email_verified = :is_email_verified', {
        is_email_verified,
      });
    }

    // Apply search
    if (search) {
      queryBuilder.andWhere(
        '(user.name ILIKE :search OR user.email ILIKE :search)',
        { search: `%${search}%` },
      );
    }

    // Apply pagination and sorting
    queryBuilder.orderBy('user.created_at', 'DESC').skip(skip).take(limit);

    // Execute query
    const [users, total] = await queryBuilder.getManyAndCount();

    // Return paginated result
    return {
      data: users,
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

  // find a user by id
  async findOne(): Promise<void> {}

  // Update user profile
  async update(): Promise<void> {}

  // delete user
  async delete(): Promise<void> {}

  async remove(): Promise<void> {}
}
