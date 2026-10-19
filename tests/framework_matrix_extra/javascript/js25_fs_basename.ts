import express from "express";
const app = express();
import fs from "fs";
import path from "path";
app.get("/u", (req, res) => {
  const name = path.basename(req.query.f as string);
  fs.readFile(path.join("/data", name), "utf8", (e, data) => res.send(data));
});
