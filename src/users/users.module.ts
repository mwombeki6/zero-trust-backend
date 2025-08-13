import { Module } from '@nestjs/common';
import { UserService } from './users.service';
import { JwtModule } from '@nestjs/jwt';

@Module({
  imports: [
    JwtModule.register({
      secret: process.env.JWT_SECRET,
      signOptions: { expiresIn: '1h' },
    }),
  ],
  controllers: [],
  providers: [UserService],
  exports: [UserService],
})
export class UsersModule {}
