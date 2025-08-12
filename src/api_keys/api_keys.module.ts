import { Module } from '@nestjs/common';
import { ApiKeysService } from './api_keys.service';
import { ApiKeysController } from './api_keys.controller';

@Module({
  controllers: [ApiKeysController],
  providers: [ApiKeysService],
})
export class ApiKeysModule {}
