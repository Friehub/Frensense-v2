import express from "express";
const app = express();
import { execFile } from "child_process";
app.get("/u", (req, res) => {
  execFile("ls", [req.query.d as string], (e, out) => res.send(out));
});
