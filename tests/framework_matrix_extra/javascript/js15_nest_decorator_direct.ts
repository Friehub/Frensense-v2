import { Controller, Get, Query } from "@nestjs/common";
import { PrismaClient } from "@prisma/client";
const prisma = new PrismaClient();
@Controller("u")
export class UController {
  @Get()
  async find(@Query("id") id: string) {
    return prisma.$queryRawUnsafe(`SELECT * FROM users WHERE id = '${id}'`);
  }
}
