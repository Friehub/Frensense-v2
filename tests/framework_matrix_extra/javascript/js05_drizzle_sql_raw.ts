import express from "express";
const app = express();
import { drizzle } from "drizzle-orm/node-postgres";
import { sql } from "drizzle-orm";
const db = drizzle(process.env.DATABASE_URL!);
app.get("/u", async (req, res) => {
  const id = req.query.id as string;
  res.json(await db.execute(sql.raw(`SELECT * FROM users WHERE id = '${id}'`)));
});
