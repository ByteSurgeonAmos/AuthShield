import {
  registerDecorator,
  ValidationOptions,
  ValidatorConstraint,
  ValidatorConstraintInterface,
  ValidationArguments,
} from 'class-validator';

@ValidatorConstraint({ async: false })
export class UsernameConstraint implements ValidatorConstraintInterface {
  validate(username: string, args: ValidationArguments) {
    if (!username) {
      return false;
    }

    const minLength = 3;
    const maxLength = 30;

    if (username.length < minLength || username.length > maxLength) {
      return false;
    }

    const usernameRegex = /^[a-zA-Z0-9_-]+$/;
    if (!usernameRegex.test(username)) {
      return false;
    }

    if (!/^[a-zA-Z0-9]/.test(username)) {
      return false;
    }

    if (/[_-]$/.test(username)) {
      return false;
    }

    if (/[_-]{2,}/.test(username)) {
      return false;
    }

    const reservedWords = [
      'admin',
      'administrator',
      'root',
      'system',
      'api',
      'bot',
      'support',
      'help',
      'moderator',
      'staff',
      'official',
      'bitcoin',
      'crypto',
      'wallet',
      'trade',
      'trading',
      'exchange',
      'binance',
      'coinbase',
      'ethereum',
      'blockchain',
      'xmobit',
    ];

    if (reservedWords.includes(username.toLowerCase())) {
      return false;
    }

    return true;
  }

  defaultMessage(args: ValidationArguments) {
    return 'Username must be 3-30 characters long, contain only letters, numbers, underscores, and hyphens, start with a letter or number, and not be a reserved word';
  }
}

export function IsValidUsername(validationOptions?: ValidationOptions) {
  return function (object: Object, propertyName: string) {
    registerDecorator({
      target: object.constructor,
      propertyName: propertyName,
      options: validationOptions,
      constraints: [],
      validator: UsernameConstraint,
    });
  };
}
