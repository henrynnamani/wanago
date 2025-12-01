import {
  createParamDecorator,
  ExecutionContext,
  Injectable,
} from '@nestjs/common';

Injectable();
export const LoggedInUser = createParamDecorator(
  (data: unknown, ctx: ExecutionContext) => {
    const request = ctx.switchToHttp().getRequest();

    const user = request.user;

    return data ? user?.data : user;
  },
);
