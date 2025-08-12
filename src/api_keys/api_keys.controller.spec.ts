import { Test, TestingModule } from '@nestjs/testing';
import { ApiKeysController } from './api_keys.controller';
import { ApiKeysService } from './api_keys.service';

describe('ApiKeysController', () => {
  let controller: ApiKeysController;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      controllers: [ApiKeysController],
      providers: [ApiKeysService],
    }).compile();

    controller = module.get<ApiKeysController>(ApiKeysController);
  });

  it('should be defined', () => {
    expect(controller).toBeDefined();
  });
});
