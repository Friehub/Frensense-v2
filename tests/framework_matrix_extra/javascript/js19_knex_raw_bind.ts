import express from "express";
const app = express();
import knex from "knex";
const db = knex({ client: "pg" });
app.get("/u", async (req, res) => {
  const id = req.query.id as string;
  res.json(await db.raw("SELECT * FROM users WHERE id = ?", [id]));
});
