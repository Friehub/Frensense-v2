import express from "express";
const app = express();
declare const cache: { query(k: string): unknown };
app.get("/u", (req, res) => {
  const id = req.query.id as string;
  res.json(cache.query(id));
});
