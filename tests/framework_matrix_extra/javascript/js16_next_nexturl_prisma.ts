import { PrismaClient } from "@prisma/client";
import { NextRequest } from "next/server";
const prisma = new PrismaClient();
export async function GET(req: NextRequest) {
  const id = req.nextUrl.searchParams.get("id");
  const rows = await prisma.$queryRawUnsafe(`SELECT * FROM users WHERE id = '${id}'`);
  return Response.json(rows);
}
