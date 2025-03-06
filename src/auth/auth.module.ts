import { JwtModule } from '@nestjs/jwt';
import { Module } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthController } from './auth.controller';
import { NatsModule } from 'src/transports/nats.module';
import { envs } from 'src/config/envs';

@Module({
  controllers: [AuthController],
  providers: [AuthService],
  imports: [
    NatsModule,
    JwtModule.register({
      global: true,
      secret: envs.jwtSecret,
      signOptions: { expiresIn: '24h' },
    }),
  ],
})
export class AuthModule {}
