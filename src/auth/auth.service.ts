import {
    ForbiddenException,
    Injectable,
    NotFoundException,
    BadGatewayException,
} from '@nestjs/common';
import { PrismaService } from 'src/prisma/prisma.service';
import { AuthDto } from './dto';
import * as argon from 'argon2';
import { PrismaClientKnownRequestError } from '@prisma/client/runtime/library';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config/dist/config.service';

@Injectable()
export class AuthService {
    constructor(
        private prisma: PrismaService,
        private jwt: JwtService,
        private config: ConfigService,
    ) {}
    async signin(dto: AuthDto) {
        try {
            const { email, password } = dto;
            const user = await this.prisma.user.findFirst({
                where: {
                    email,
                },
            });
            if (!user) throw new ForbiddenException('user not found');
            const decode = await argon.verify(user.hash, password);
            if (!decode)
                throw new BadGatewayException(
                    'email or password is not valid please try again',
                );
            return this.signToken(user.id, user.email);
        } catch (err) {
            throw err;
        }
    }
    async signup(dto: AuthDto) {
        const hash = await argon.hash(dto.password);
        try {
            const data = { email: dto.email, hash };
            const user = await this.prisma.user.create({ data });
            return this.signToken(user.id, user.email);
        } catch (err) {
            if (err instanceof PrismaClientKnownRequestError) {
                if (err.code === 'P2002') {
                    throw new ForbiddenException('creadentials taken');
                }
            }
            throw err;
        }
    }

    async signToken(
        userId: number,
        email: string,
    ): Promise<{ access_token: string }> {
        const payload = {
            sub: userId,
            email,
        };
        const token = await this.jwt.signAsync(payload, {
            expiresIn: '1h',
            secret: this.config.get('JWT_SECRET'),
        });
        return {
            access_token: token,
        };
    }
}
