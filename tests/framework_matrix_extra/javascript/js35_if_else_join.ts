import express from "express";
const app = express();
import { Pool } from "pg";
const pool = new Pool();
app.get("/u", async (req, res) => {
  let id: string;
  if (req.query.id) { id = req.query.id as string; } else { id = "0"; }
  res.json(await pool.query("SELECT * FROM users WHERE id = " + id));
});
