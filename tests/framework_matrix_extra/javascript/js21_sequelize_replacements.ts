import express from "express";
const app = express();
import { Sequelize } from "sequelize";
const sequelize = new Sequelize("sqlite::memory:");
app.get("/u", async (req, res) => {
  const id = req.query.id as string;
  res.json(await sequelize.query("SELECT * FROM users WHERE id = :id", { replacements: { id } }));
});
