import express from "express";
import { Pool } from "pg";
const app = express();
const x = new Pool();
app.get("/u", async (req, res) => {
  const id = req.query.id as string;
  res.json(await x.query("SELECT * FROM users WHERE id = '" + id + "'"));
});
