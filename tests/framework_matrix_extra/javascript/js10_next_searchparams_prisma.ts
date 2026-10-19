import { PrismaClient } from "@prisma/client";
const prisma = new PrismaClient();
export async function GET(req: Request) {
  const id = new URL(req.url).searchParams.get("id");
  const rows = await prisma.$queryRawUnsafe(`SELECT * FROM users WHERE id = '${id}'`);
  return Response.json(rows);
}
