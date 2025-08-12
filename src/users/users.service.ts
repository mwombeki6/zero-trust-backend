import {
  BadRequestException,
  ConflictException,
  Injectable,
} from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';
import { CreateUserDto } from './dto/create-user.dto';
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
  async findAll(): Promise<void> {}

  // find a user by id
  async findOne(): Promise<void> {}

  // Update user profile
  async update(): Promise<void> {}

  // delete user
  async delete(): Promise<void> {}

  async remove(): Promise<void> {}
}
