package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/banking-superapp/auth-service/config"
	"github.com/banking-superapp/auth-service/handler"
	"github.com/banking-superapp/auth-service/middleware"
	"github.com/banking-superapp/auth-service/repository"
	"github.com/banking-superapp/auth-service/service"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	fiberlogger "github.com/gofiber/fiber/v2/middleware/logger"
	"github.com/gofiber/fiber/v2/middleware/recover"
	"github.com/redis/go-redis/v9"
)

func main() {
	cfg := config.Load()

	mongoClient, err := repository.NewMongoClient(cfg.MongoAtlasURI)
	if err != nil {
		log.Fatalf("Failed to connect to MongoDB: %v", err)
	}
	defer mongoClient.Disconnect(context.Background())

	db := mongoClient.Database("banking_auth")
	if err := repository.CreateIndexes(db); err != nil {
		log.Fatalf("Failed to create indexes: %v", err)
	}

	opt, err := redis.ParseURL(cfg.RedisURL)
	if err != nil {
		log.Fatalf("Failed to parse Redis URL: %v", err)
	}
	redisClient := redis.NewClient(opt)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := redisClient.Ping(ctx).Err(); err != nil {
		log.Fatalf("Failed to connect to Redis: %v", err)
	}

	jwtSvc, err := service.NewJWTService(
		cfg.JWTPrivateKey, cfg.JWTPublicKey,
		cfg.AccessTokenExpiry, cfg.RefreshTokenExpiry,
	)
	if err != nil {
		log.Fatalf("Failed to init JWT service: %v", err)
	}

	userRepo := repository.NewUserRepository(db)
	otpRepo := repository.NewOTPRepository(db)
	deviceRepo := repository.NewDeviceRepository(db)
	sessionRepo := repository.NewSessionRepository(db)

	otpSvc := service.NewOTPService(otpRepo, cfg.OTPExpiryMinutes)
	authSvc := service.NewAuthService(
		userRepo, sessionRepo, deviceRepo, jwtSvc, redisClient,
		cfg.MPINMaxAttempts, cfg.AccessTokenExpiry, cfg.RefreshTokenExpiry,
	)

	authHandler := handler.NewAuthHandler(authSvc, otpSvc)

	app := fiber.New(fiber.Config{
		AppName:      cfg.ServiceName,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
	})

	app.Use(recover.New())
	app.Use(fiberlogger.New())
	app.Use(cors.New())

	app.Get("/health", func(c *fiber.Ctx) error {
		return c.JSON(fiber.Map{"status": "ok", "service": cfg.ServiceName})
	})

	v1 := app.Group("/v1/auth")
	// Public routes
	v1.Post("/send-otp", authHandler.SendOTP)
	v1.Post("/verify-otp", authHandler.VerifyOTP)
	v1.Post("/login/mpin", authHandler.LoginMPIN)
	v1.Post("/login/biometric", authHandler.LoginBiometric)
	v1.Post("/refresh", authHandler.RefreshToken)

	// Protected routes
	protected := v1.Group("", middleware.JWTAuth(jwtSvc))
	protected.Post("/set-mpin", authHandler.SetMPIN)
	protected.Post("/logout", authHandler.Logout)
	protected.Post("/device/bind", authHandler.BindDevice)

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		if err := app.Listen(fmt.Sprintf(":%s", cfg.Port)); err != nil {
			log.Printf("Server error: %v", err)
		}
	}()

	log.Printf("%s started on :%s", cfg.ServiceName, cfg.Port)
	<-quit
	log.Println("Shutting down gracefully...")
	if err := app.ShutdownWithTimeout(10 * time.Second); err != nil {
		log.Printf("Shutdown error: %v", err)
	}
}
