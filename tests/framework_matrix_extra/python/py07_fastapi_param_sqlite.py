from fastapi import FastAPI
import sqlite3
app = FastAPI()
@app.get("/u")
async def u(id: str):
    conn = sqlite3.connect("x.db")
    return conn.execute("SELECT * FROM t WHERE id = '" + id + "'").fetchall()
