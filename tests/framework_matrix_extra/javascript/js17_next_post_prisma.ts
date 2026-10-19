import { PrismaClient } from "@prisma/client";
const prisma = new PrismaClient();
export async function POST(req: Request) {
  const body = await req.json();
  const rows = await prisma.$queryRawUnsafe(`SELECT * FROM users WHERE id = '${body.id}'`);
  return Response.json(rows);
}
