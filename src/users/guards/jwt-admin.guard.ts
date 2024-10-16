import {
  Injectable,
  CanActivate,
  ExecutionContext,
  ForbiddenException,
} from '@nestjs/common';
import { AuthGuard } from './jwt-auth.guard';

@Injectable()
export class AdminGuard extends AuthGuard implements CanActivate {
  canActivate(context: ExecutionContext): boolean {
    const isAuthenticated = super.canActivate(context);
    if (!isAuthenticated) {
      return false;
    }

    const request = context.switchToHttp().getRequest();
    const user = request.user;

    if (user.role !== 'admin') {
      throw new ForbiddenException('Admin access required');
    }
    return true;
  }
}
