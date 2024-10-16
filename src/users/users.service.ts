import {
  BadRequestException,
  Injectable,
  NotFoundException,
  UnauthorizedException,
} from '@nestjs/common';
import { CreateUserDto } from './dto/create-user.dto';
import { UpdateUserDto } from './dto/update-user.dto';
import { Repository } from 'typeorm';
import { User } from './entities/user.entity';
import { InjectRepository } from '@nestjs/typeorm';
import * as bcrypt from 'bcrypt';
import { LoginUserDto } from './dto/login-user.dto';
import { JwtService } from '@nestjs/jwt';
import * as nodemailer from 'nodemailer';
import { randomBytes } from 'crypto';

@Injectable()
export class UsersService {
  constructor(
    @InjectRepository(User) private userRepository: Repository<User>,
    private jwtService: JwtService,
  ) {}

  async findAll(): Promise<User[]> {
    const users = await this.userRepository.find();
    return users;
  }

  async findOne(id: number): Promise<User> {
    const user = await this.userRepository.findOne({ where: { id: id } });
    return user;
  }

  async update(id: number, updateUserDto: UpdateUserDto) {
    const user = await this.userRepository.preload({
      id: id,
      ...updateUserDto,
    });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    return this.userRepository.save(user);
  }

  async remove(id: number): Promise<void> {
    const resp = await this.userRepository.delete(id);
    if (resp.affected === 0) {
      throw new NotFoundException(`User with ID ${id} not found`);
    }
  }
  async login(loginDto: LoginUserDto): Promise<{ accesstoken: string }> {
    const userExists = await this.userRepository.findOne({
      where: { email: loginDto.email },
    });
    if (!userExists) {
      throw new NotFoundException('User not found');
    }
    const isPasswordValid = await bcrypt.compare(
      loginDto.password,
      userExists.password,
    );
    if (!isPasswordValid) {
      userExists.lastFailedLogin = new Date();
      userExists.loginAttempts++;
      await this.userRepository.save(userExists);
      throw new UnauthorizedException('Invalid credentials');
    }
    if (!userExists.isActive) {
      throw new UnauthorizedException('User is not active');
    }
    if (!userExists.isEmailVerified) {
      throw new UnauthorizedException('Email is not verified');
    }
    if (userExists.loginAttempts > 5) {
      throw new UnauthorizedException(
        'Too many failed login attempts please wait 10 mins before continuing',
      );
    }
    userExists.loginAttempts = 0;
    userExists.lastLogin = new Date();
    await this.userRepository.save(userExists);
    const payload = {
      userId: userExists.id,
      email: userExists.email,
      username: userExists.username,
      role: userExists.isAdmin ? 'admin' : 'user',
    };
    return {
      accesstoken: this.jwtService.sign(payload),
    };
  }
  async sendVerificationEmail(email: string, token: string) {
    const transporter = nodemailer.createTransport({
      host: 'smtp.gmail.com',
      secure: true,
      port: 465,
      auth: {
        user: 'amoswachira16@gmail.com',
        pass: 'gyzm hjdf qjli hlve',
      },
    });

    const verificationLink = `http://localhost:3000/users/verify?token=${token}`;

    const htmlContent = `
      <div style="text-align: center;">
        <img src="cid:logo" alt="Logo" style="width: 100px;" />
        <h2>Welcome to Our Service!</h2>
        <p>Please click the link below to verify your email:</p>
        <a href="${verificationLink}" style="background-color: #4CAF50; padding: 10px; color: white; text-decoration: none; border-radius: 5px;">Verify Email</a>
      </div>
    `;

    await transporter.sendMail({
      from: 'no-reply@app.com',
      to: email,
      subject: 'Verify Your Email',
      html: htmlContent,
      attachments: [
        {
          filename: 'logo.svg',
          path: './logo.svg',
          cid: 'logo',
        },
      ],
    });
  }

  async create(createUserDto: CreateUserDto) {
    const userExists = await this.userRepository.findOne({
      where: { email: createUserDto.email },
    });
    if (userExists) {
      throw new BadRequestException('Email already exists');
    }

    const userNameExists = await this.userRepository.findOne({
      where: { username: createUserDto.username },
    });
    if (userNameExists) {
      throw new BadRequestException('Username already exists');
    }

    const hashedPassword = await bcrypt.hash(createUserDto.password, 10);
    const verificationToken = randomBytes(32).toString('hex');
    const tokenExpiry = new Date();
    tokenExpiry.setHours(tokenExpiry.getHours() + 24);

    const user = this.userRepository.create({
      ...createUserDto,
      password: hashedPassword,
      verificationToken,
      verificationTokenExpires: tokenExpiry,
    });

    await this.sendVerificationEmail(user.email, user.verificationToken);
    return await this.userRepository.save(user);
  }

  async resendVerificationToken(email: string): Promise<{ message: string }> {
    const user = await this.userRepository.findOne({ where: { email } });

    if (!user) {
      throw new NotFoundException('User not found');
    }

    if (user.isEmailVerified) {
      throw new BadRequestException('Email is already verified');
    }

    const newVerificationToken = randomBytes(32).toString('hex');
    const tokenExpiry = new Date();
    tokenExpiry.setHours(tokenExpiry.getHours() + 24);

    user.verificationToken = newVerificationToken;
    user.verificationTokenExpires = tokenExpiry;

    await this.userRepository.save(user);
    await this.sendVerificationEmail(user.email, user.verificationToken);

    return { message: 'Verification token resent successfully' };
  }
  async verifyEmail(token: string): Promise<{ message: string }> {
    const user = await this.userRepository.findOne({
      where: { verificationToken: token },
    });

    if (!user) {
      throw new NotFoundException('Invalid or expired verification token');
    }

    const currentTime = new Date();
    if (currentTime > user.verificationTokenExpires) {
      throw new BadRequestException(
        'Verification token has expired. Please request a new token.',
      );
    }

    if (user.isEmailVerified) {
      throw new BadRequestException('Email is already verified');
    }

    user.isEmailVerified = true;
    user.verificationToken = null;
    user.verificationTokenExpires = null;

    await this.userRepository.save(user);

    return { message: 'Email verified successfully' };
  }
}
