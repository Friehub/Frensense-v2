import express from "express";
const app = express();
import { exec } from "child_process";
app.get("/u", (req, res) => {
  exec("ls " + (req.query.d as string), (e, out) => res.send(out));
});
