import { Controller, Post, Body } from '@nestjs/common';
import { AuthService } from './auth.service';
import { AuthDto } from './dto';

@Controller('auth')
export class AuthController {
    constructor(private authservice: AuthService) {}

    @Post('signin')
    signin(@Body() dto: any) {
        return this.authservice.signin(dto);
    }

    @Post('signup')
    signup(@Body() dto: AuthDto) {
        // req.user
        return this.authservice.signup(dto);
    }
}
