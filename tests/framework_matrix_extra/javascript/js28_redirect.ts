import express from "express";
const app = express();
app.get("/u", (req, res) => {
  res.redirect(req.query.next as string);
});
