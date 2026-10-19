import { Controller, Get, Query } from "@nestjs/common";
import { PrismaService } from "./prisma.service";
@Controller("u")
export class UController {
  constructor(private readonly prisma: PrismaService) {}
  @Get()
  async find(@Query("id") id: string) {
    return this.prisma.$queryRawUnsafe(`SELECT * FROM users WHERE id = '${id}'`);
  }
}
