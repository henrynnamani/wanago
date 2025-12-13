import { Test, TestingModule } from '@nestjs/testing';
import { TwoFactorAuthenticatorService } from './two-factor-authenticator.service';

describe('TwoFactorAuthenticatorService', () => {
  let service: TwoFactorAuthenticatorService;

  beforeEach(async () => {
    const module: TestingModule = await Test.createTestingModule({
      providers: [TwoFactorAuthenticatorService],
    }).compile();

    service = module.get<TwoFactorAuthenticatorService>(TwoFactorAuthenticatorService);
  });

  it('should be defined', () => {
    expect(service).toBeDefined();
  });
});
