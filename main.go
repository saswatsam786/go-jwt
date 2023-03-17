package main

import (
	"os"

	"github.com/gin-gonic/gin"
	"github.com/saswatsam786/golang-jwt/routes"
)

func main() {

	port := os.Getenv("PORT")

	if port == "" {
		port = "8080"
	}

	router := gin.New()
	router.Use(gin.Logger())

	router.GET("/", func(c *gin.Context) {
		c.JSON(200, "Welcome to the Golang JWT Authentication API")
	})

	routes.AuthRoutes(router)
	routes.UserRoutes(router)

	router.GET("/api-1", func(c *gin.Context) {
		c.JSON(200, gin.H{"success": "Access granted for API-1"})
	})

	router.GET("/api-2", func(c *gin.Context) {
		c.JSON(200, gin.H{"success": "Access granted for API-2"})
	})

	router.Run(":" + port)
}
