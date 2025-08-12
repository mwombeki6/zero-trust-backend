import {
  BadRequestException,
  ConflictException,
  Injectable,
} from '@nestjs/common';
import * as bcrypt from 'bcrypt';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User, UserRole } from './entities/user.entity';

@Injectable()
export class UsersService {
  create(createUserDto: CreateUserDto) {
    return 'This action adds a new user';
  }

  findAll() {
    return `This action returns all users`;
  }

  findOne(id: number) {
    return `This action returns a #${id} user`;
  }

  update(id: number, updateUserDto: UpdateUserDto) {
    return `This action updates a #${id} user`;
  }

  remove(id: number) {
    return `This action removes a #${id} user`;
  }
}

@Injectable()
export class UserService {
  constructor(
    @InjectRepository(User)
    private readonly userRepository: Repository<User>,
  ) {}

  // Create a new user
  async create(userData: CreateUserDto): Promise<void> {
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
      return this.jwt
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
