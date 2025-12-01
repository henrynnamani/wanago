import { Request } from 'express';
import { User } from 'src/users/model/user.entity';

export interface RequestWithUser extends Request {
  user: User;
}
