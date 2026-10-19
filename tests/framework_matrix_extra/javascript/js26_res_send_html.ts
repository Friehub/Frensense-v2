import express from "express";
const app = express();
app.get("/u", (req, res) => {
  res.send("<h1>" + (req.query.n as string) + "</h1>");
});
