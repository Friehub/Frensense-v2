import express from "express";
const app = express();
import { Pool } from "pg";
const pool = new Pool();
app.get("/u", async (req, res) => {
  const id = Number(req.query.id);
  res.json(await pool.query("SELECT * FROM users WHERE id = " + id));
});
