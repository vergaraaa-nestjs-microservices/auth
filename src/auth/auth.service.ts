import { Injectable, Logger, OnModuleInit } from '@nestjs/common';
import { RpcException } from '@nestjs/microservices';
import { PrismaClient } from '@prisma/client';
import { RegisterUserDto } from './dto/register-user.dto';
import * as bcrypt from 'bcrypt';
import { LoginUserDto } from './dto/login-user.dto';
import { JwtService } from '@nestjs/jwt';
import { JwtPayload } from './interfaces/jwt-payload.interface';

@Injectable()
export class AuthService extends PrismaClient implements OnModuleInit {
  private readonly logger = new Logger('AuthService');

  constructor(private readonly jwtService: JwtService) {
    super();
  }

  async onModuleInit() {
    await this.$connect();
    this.logger.log('MongoDB connected');
  }

  async registerUser(registerUserDto: RegisterUserDto) {
    const { name, email, password } = registerUserDto;

    try {
      const user = await this.user.findUnique({
        where: { email },
      });

      if (user) {
        throw new RpcException({
          status: 400,
          message: 'User already exists',
        });
      }

      const newUser = await this.user.create({
        data: {
          email,
          password: bcrypt.hashSync(password, 10),
          name,
        },
      });

      const { password: _, ...rest } = newUser;

      void _;

      return {
        user: rest,
        token: this.signJwt(rest),
      };
    } catch (error) {
      if (error instanceof Error) {
        throw new RpcException({
          status: 400,
          message: error.message,
        });
      }

      throw new RpcException({
        status: 500,
        message: 'Unknown error in auth.service - Auth Microservice',
      });
    }
  }

  async loginUser(loginUserDto: LoginUserDto) {
    const { email, password } = loginUserDto;

    try {
      const user = await this.user.findUnique({
        where: { email },
      });

      if (!user) {
        throw new RpcException({
          status: 400,
          message: 'Invalid credentials',
        });
      }

      const isPasswordMatch = bcrypt.compareSync(password, user.password);

      if (!isPasswordMatch) {
        throw new RpcException({
          status: 400,
          message: 'Invalid credentials',
        });
      }

      const { password: _, ...rest } = user;

      void _;

      return {
        user: rest,
        token: this.signJwt(rest),
      };
    } catch (error) {
      if (error instanceof Error) {
        throw new RpcException({
          status: 400,
          message: error.message,
        });
      }

      throw new RpcException({
        status: 500,
        message: 'Unknown error in auth.service - Auth Microservice',
      });
    }
  }

  signJwt(payload: JwtPayload) {
    return this.jwtService.sign(payload);
  }
}
