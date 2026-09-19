import { Controller, Get } from '@nestjs/common';
import { AuthorizationJwtService } from './authorization-jwt.service';

@Controller('.well-known')
export class JwksController {
  constructor(private readonly jwtService: AuthorizationJwtService) {}

  @Get('jwks.json')
  async jwks() {
    return this.jwtService.buildJwks();
  }
}
