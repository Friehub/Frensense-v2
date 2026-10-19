import { Hono } from "hono";
import { Pool } from "pg";
const app = new Hono();
const pool = new Pool();
app.get("/u", async (c) => {
  const id = c.req.query("id");
  return c.json(await pool.query("SELECT * FROM users WHERE id = '" + id + "'"));
});
