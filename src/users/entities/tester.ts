import { ConflictException, Injectable, NotFoundException } from '@nestjs/common';
import { InjectRepository } from '@nestjs/typeorm';
import { Repository } from 'typeorm';
import { User, UserType } from './user.entity';
import { CreateUserDto } from './dto/create-user.dto';
import { CreateStationOwnerDto } from './dto/create-user.dto';
import * as bcrypt from 'bcrypt';
import { JwtService } from '@nestjs/jwt';

@Injectable()
export class UserService {
  constructor(
    @InjectRepository(User)
    private userRepository: Repository<User>,
    private jwtService: JwtService,
  ) {}

  async createAdminUser(email: string, password: string, fullName: string): Promise<User> {
    const hashedPassword = await bcrypt.hash(password, 10);

    const admin = new User();
    admin.email = email;
    admin.password = hashedPassword;
    admin.fullName = fullName;
    admin.role = UserType.ADMIN;

    return this.userRepository.save(admin);
  }

  async createStationOwner(userData: CreateStationOwnerDto): Promise<string> {
    const existing = await this.userRepository.findOne({ where: { email: userData.email } });
    if (existing) throw new ConflictException('Email already exists');

    const hashed = await bcrypt.hash(userData.password, 10);
    const user = this.userRepository.create({
      email: userData.email,
      password: hashed,
      role: UserType.STATION_OWNER,
    });

    await this.userRepository.save(user);
    return this.jwtService.signAsync({
      sub: user.id,
      email: user.email,
      role: user.role,
    });
  }

  async create(userData: CreateUserDto): Promise<User> {
    const user = this.userRepository.create(userData);
    return this.userRepository.save(user);
  }

  async getByPhoneNumber(phoneNumber: string): Promise<User | null> {
    return this.userRepository.findOne({ where: { phoneNumber } });
  }

  async getById(id: number): Promise<User> {
    const user = await this.userRepository.findOne({ where: { id } });
    if (!user) {
      throw new NotFoundException(`User with ID ${id} not found`);
    }
    return user;
  }

  async markPhoneNumberAsConfirmed(userId: number): Promise<User> {
    const user = await this.getById(userId); // Ensure user exists

    user.isPhoneNumberConfirmed = true;
    return this.userRepository.save(user); // Save and return updated user
  }

  async update(userId: number, updateData: Partial<User>): Promise<User> {
    await this.userRepository.update({ id: userId }, updateData);
    return this.getById(userId);
  }

  async getByEmail(email: string): Promise<User | null> {
    return this.userRepository.findOne({ where: { email } });
  }

  async updateLastLogin(userId: number) {
    await this.userRepository.update(userId, {
      lastLogin: new Date(),
    });
  }

  async createStationOwner(userData: CreateStationOwnerDto): Promise<string> {
    // Input validation
    if (!userData.email || !userData.password) {
      throw new BadRequestException('Email and password are required');
    }

    const sanitizedEmail = userData.email.toLowerCase().trim();

    // Use database transaction
    return await this.userRepository.manager.transaction(async (manager) => {
      // Check for duplicates within transaction
      const existing = await manager.findOne(User, {
        where: { email: sanitizedEmail }
      });
      if (existing) {
        throw new ConflictException('Email already exists');
      }

      // Stronger hashing
      const hashed = await bcrypt.hash(userData.password, 12);

      const user = manager.create(User, {
        email: sanitizedEmail,
        password: hashed,
        role: UserType.STATION_OWNER,
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
}

