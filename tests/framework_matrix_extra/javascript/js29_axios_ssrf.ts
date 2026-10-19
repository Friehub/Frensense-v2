import express from "express";
const app = express();
import axios from "axios";
app.get("/u", async (req, res) => {
  res.send((await axios.get(req.query.u as string)).data);
});
