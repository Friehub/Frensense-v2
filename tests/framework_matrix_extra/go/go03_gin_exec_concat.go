package main

import (
	"database/sql"
	"github.com/gin-gonic/gin"
)

var db *sql.DB

func h(c *gin.Context) {
	id := c.Query("id")
	db.Exec("DELETE FROM t WHERE id = " + id)
}
