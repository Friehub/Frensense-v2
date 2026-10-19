import express from "express";
const app = express();
declare const helper: any;
app.get("/u", async (req, res) => {
  const id = req.query.id as string;
  res.json(await helper.$queryRawUnsafe(`SELECT * FROM users WHERE id = '${id}'`));
});
