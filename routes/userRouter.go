package routes

import (
	"github.com/gin-gonic/gin"
	"github.com/saswatsam786/golang-jwt/controllers"
	"github.com/saswatsam786/golang-jwt/middleware"
)

func UserRoutes(incomingRoutes *gin.Engine) {
	incomingRoutes.Use(middleware.Authenticate())
	incomingRoutes.GET("/users", controllers.GetUsers())
	incomingRoutes.GET("users/:user_id", controllers.GetUser())
}
