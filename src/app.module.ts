import { Module } from '@nestjs/common';
import { AppController } from './app.controller';
import { AppService } from './app.service';
import { AuthModule } from './auth/auth.module';
import { UsersModule } from './users/users.module';
import { ApiKeysModule } from './api_keys/api_keys.module';
import { DataModule } from './data/data.module';
import { BlockchainModule } from './blockchain/blockchain.module';

@Module({
  imports: [
    AuthModule,
    UsersModule,
    ApiKeysModule,
    DataModule,
    BlockchainModule,
  ],
  controllers: [AppController],
  providers: [AppService],
})
export class AppModule {}
