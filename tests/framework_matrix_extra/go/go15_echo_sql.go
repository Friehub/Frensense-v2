package main

import (
	"database/sql"
	"github.com/labstack/echo/v4"
)

var db *sql.DB

func h(c echo.Context) error {
	id := c.QueryParam("id")
	db.Query("SELECT * FROM users WHERE id = " + id)
	return nil
}
