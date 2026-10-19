import express from "express";
const app = express();
app.get("/u", (req, res) => {
  res.json({ n: req.query.n });
});
