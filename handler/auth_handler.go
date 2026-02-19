package handler

import (
	"github.com/banking-superapp/auth-service/model"
	"github.com/banking-superapp/auth-service/service"
	"github.com/gofiber/fiber/v2"
	"go.mongodb.org/mongo-driver/v2/bson"
)

type AuthHandler struct {
	authSvc service.AuthService
	otpSvc  service.OTPService
}

func NewAuthHandler(authSvc service.AuthService, otpSvc service.OTPService) *AuthHandler {
	return &AuthHandler{authSvc: authSvc, otpSvc: otpSvc}
}

func respond(c *fiber.Ctx, status int, data interface{}) error {
	return c.Status(status).JSON(fiber.Map{"success": status < 400, "data": data})
}

func respondErr(c *fiber.Ctx, status int, message string) error {
	return c.Status(status).JSON(fiber.Map{"success": false, "error": message})
}

func (h *AuthHandler) SendOTP(c *fiber.Ctx) error {
	var req model.SendOTPRequest
	if err := c.BodyParser(&req); err != nil {
		return respondErr(c, fiber.StatusBadRequest, "invalid request body")
	}
	if len(req.Mobile) != 10 {
		return respondErr(c, fiber.StatusBadRequest, "mobile must be 10 digits")
	}
	if err := h.otpSvc.SendOTP(c.Context(), req.Mobile); err != nil {
		return respondErr(c, fiber.StatusInternalServerError, "failed to send OTP")
	}
	return respond(c, fiber.StatusOK, fiber.Map{"message": "OTP sent successfully"})
}

func (h *AuthHandler) VerifyOTP(c *fiber.Ctx) error {
	var req model.VerifyOTPRequest
	if err := c.BodyParser(&req); err != nil {
		return respondErr(c, fiber.StatusBadRequest, "invalid request body")
	}
	verified, err := h.otpSvc.VerifyOTP(c.Context(), req.Mobile, req.OTP)
	if err != nil {
		return respondErr(c, fiber.StatusInternalServerError, "verification failed")
	}
	if !verified {
		return respondErr(c, fiber.StatusUnauthorized, "invalid or expired OTP")
	}
	user, err := h.authSvc.CreateOrGetUser(c.Context(), req.Mobile)
	if err != nil {
		return respondErr(c, fiber.StatusInternalServerError, "failed to create user")
	}
	return respond(c, fiber.StatusOK, fiber.Map{
		"message": "OTP verified",
		"user_id": user.ID.Hex(),
		"status":  user.Status,
	})
}

func (h *AuthHandler) SetMPIN(c *fiber.Ctx) error {
	userIDStr, ok := c.Locals("user_id").(string)
	if !ok {
		return respondErr(c, fiber.StatusUnauthorized, "unauthorized")
	}
	userID, err := bson.ObjectIDFromHex(userIDStr)
	if err != nil {
		return respondErr(c, fiber.StatusUnauthorized, "invalid user")
	}
	var req model.SetMPINRequest
	if err := c.BodyParser(&req); err != nil {
		return respondErr(c, fiber.StatusBadRequest, "invalid request body")
	}
	if len(req.MPIN) < 4 || len(req.MPIN) > 6 {
		return respondErr(c, fiber.StatusBadRequest, "MPIN must be 4-6 digits")
	}
	if err := h.authSvc.SetMPIN(c.Context(), userID, req.MPIN); err != nil {
		return respondErr(c, fiber.StatusInternalServerError, "failed to set MPIN")
	}
	return respond(c, fiber.StatusOK, fiber.Map{"message": "MPIN set successfully"})
}

func (h *AuthHandler) LoginMPIN(c *fiber.Ctx) error {
	var req model.LoginMPINRequest
	if err := c.BodyParser(&req); err != nil {
		return respondErr(c, fiber.StatusBadRequest, "invalid request body")
	}
	resp, err := h.authSvc.LoginWithMPIN(c.Context(), req.Mobile, req.MPIN, req.DeviceID)
	if err != nil {
		switch err {
		case service.ErrAccountLocked:
			return respondErr(c, fiber.StatusTooManyRequests, err.Error())
		case service.ErrInvalidMPIN, service.ErrUserNotFound:
			return respondErr(c, fiber.StatusUnauthorized, "invalid credentials")
		default:
			return respondErr(c, fiber.StatusInternalServerError, "login failed")
		}
	}
	return respond(c, fiber.StatusOK, resp)
}

func (h *AuthHandler) LoginBiometric(c *fiber.Ctx) error {
	var req model.BiometricLoginRequest
	if err := c.BodyParser(&req); err != nil {
		return respondErr(c, fiber.StatusBadRequest, "invalid request body")
	}
	resp, err := h.authSvc.LoginWithBiometric(c.Context(), req.DeviceID, req.SecureKey)
	if err != nil {
		return respondErr(c, fiber.StatusUnauthorized, "biometric authentication failed")
	}
	return respond(c, fiber.StatusOK, resp)
}

func (h *AuthHandler) RefreshToken(c *fiber.Ctx) error {
	var req model.RefreshTokenRequest
	if err := c.BodyParser(&req); err != nil {
		return respondErr(c, fiber.StatusBadRequest, "invalid request body")
	}
	resp, err := h.authSvc.RefreshToken(c.Context(), req.RefreshToken)
	if err != nil {
		return respondErr(c, fiber.StatusUnauthorized, "invalid or expired refresh token")
	}
	return respond(c, fiber.StatusOK, resp)
}

func (h *AuthHandler) Logout(c *fiber.Ctx) error {
	userIDStr, ok := c.Locals("user_id").(string)
	if !ok {
		return respondErr(c, fiber.StatusUnauthorized, "unauthorized")
	}
	userID, err := bson.ObjectIDFromHex(userIDStr)
	if err != nil {
		return respondErr(c, fiber.StatusUnauthorized, "invalid user")
	}
	if err := h.authSvc.Logout(c.Context(), userID); err != nil {
		return respondErr(c, fiber.StatusInternalServerError, "logout failed")
	}
	return respond(c, fiber.StatusOK, fiber.Map{"message": "logged out successfully"})
}

func (h *AuthHandler) BindDevice(c *fiber.Ctx) error {
	userIDStr, ok := c.Locals("user_id").(string)
	if !ok {
		return respondErr(c, fiber.StatusUnauthorized, "unauthorized")
	}
	userID, err := bson.ObjectIDFromHex(userIDStr)
	if err != nil {
		return respondErr(c, fiber.StatusUnauthorized, "invalid user")
	}
	var req model.BindDeviceRequest
	if err := c.BodyParser(&req); err != nil {
		return respondErr(c, fiber.StatusBadRequest, "invalid request body")
	}
	if err := h.authSvc.BindDevice(c.Context(), userID, &req); err != nil {
		return respondErr(c, fiber.StatusInternalServerError, "device binding failed")
	}
	return respond(c, fiber.StatusOK, fiber.Map{"message": "device bound successfully"})
}
