import express from "express";
const app = express();
import { PrismaClient } from "@prisma/client";
const prisma = new PrismaClient();
app.get("/u", async (req, res) => {
  const id = req.query.id as string;
  res.json(await prisma.$queryRaw`SELECT * FROM users WHERE id = ${id}`);
});
