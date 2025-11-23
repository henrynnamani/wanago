import { Request } from '@nestjs/common';
import { Response } from 'express';
import { User } from 'src/users/user.entity';

export interface RequestWithUser extends Request {
  user: User;
  res: Response;
}
