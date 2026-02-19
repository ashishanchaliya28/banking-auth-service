package middleware

import (
	"strings"

	"github.com/banking-superapp/auth-service/service"
	"github.com/gofiber/fiber/v2"
)

func JWTAuth(jwtSvc service.JWTService) fiber.Handler {
	return func(c *fiber.Ctx) error {
		authHeader := c.Get("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"success": false,
				"error":   "missing or invalid authorization header",
			})
		}
		token := strings.TrimPrefix(authHeader, "Bearer ")
		claims, err := jwtSvc.ValidateToken(token)
		if err != nil {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"success": false,
				"error":   "invalid or expired token",
			})
		}
		if claims.Type != "access" {
			return c.Status(fiber.StatusUnauthorized).JSON(fiber.Map{
				"success": false,
				"error":   "invalid token type",
			})
		}
		c.Locals("user_id", claims.UserID)
		c.Locals("mobile", claims.Mobile)
		return c.Next()
	}
}
