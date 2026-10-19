import express from "express";
const app = express();
import fs from "fs";
app.get("/u", (req, res) => {
  fs.readFile(req.query.f as string, "utf8", (e, data) => res.send(data));
});
