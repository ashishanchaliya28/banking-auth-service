package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/banking-superapp/auth-service/model"
	"github.com/banking-superapp/auth-service/repository"
	"github.com/redis/go-redis/v9"
	"go.mongodb.org/mongo-driver/v2/bson"
	"golang.org/x/crypto/bcrypt"
)

var (
	ErrUserNotFound   = errors.New("user not found")
	ErrInvalidMPIN    = errors.New("invalid mpin")
	ErrAccountLocked  = errors.New("account locked due to too many failed attempts")
	ErrInvalidDevice  = errors.New("device not recognized")
	ErrInvalidSession = errors.New("invalid or expired session")
	ErrMPINNotSet     = errors.New("mpin not set")
)

type AuthService interface {
	CreateOrGetUser(ctx context.Context, mobile string) (*model.User, error)
	SetMPIN(ctx context.Context, userID bson.ObjectID, mpin string) error
	LoginWithMPIN(ctx context.Context, mobile, mpin, deviceID string) (*model.AuthResponse, error)
	LoginWithBiometric(ctx context.Context, deviceID, secureKey string) (*model.AuthResponse, error)
	RefreshToken(ctx context.Context, refreshToken string) (*model.AuthResponse, error)
	Logout(ctx context.Context, userID bson.ObjectID) error
	BindDevice(ctx context.Context, userID bson.ObjectID, req *model.BindDeviceRequest) error
}

type authService struct {
	userRepo    repository.UserRepository
	sessionRepo repository.SessionRepository
	deviceRepo  repository.DeviceRepository
	jwtSvc      JWTService
	redis       *redis.Client
	maxAttempts int
	accessExp   int
	refreshExp  int
}

func NewAuthService(
	userRepo repository.UserRepository,
	sessionRepo repository.SessionRepository,
	deviceRepo repository.DeviceRepository,
	jwtSvc JWTService,
	redisClient *redis.Client,
	maxAttempts, accessExp, refreshExp int,
) AuthService {
	return &authService{
		userRepo:    userRepo,
		sessionRepo: sessionRepo,
		deviceRepo:  deviceRepo,
		jwtSvc:      jwtSvc,
		redis:       redisClient,
		maxAttempts: maxAttempts,
		accessExp:   accessExp,
		refreshExp:  refreshExp,
	}
}

func (s *authService) CreateOrGetUser(ctx context.Context, mobile string) (*model.User, error) {
	user, err := s.userRepo.FindByMobile(ctx, mobile)
	if err != nil {
		return nil, err
	}
	if user != nil {
		return user, nil
	}
	newUser := &model.User{
		Mobile: mobile,
		Status: model.UserStatusPending,
	}
	if err := s.userRepo.Create(ctx, newUser); err != nil {
		return nil, err
	}
	return newUser, nil
}

func (s *authService) SetMPIN(ctx context.Context, userID bson.ObjectID, mpin string) error {
	hash, err := bcrypt.GenerateFromPassword([]byte(mpin), bcrypt.DefaultCost)
	if err != nil {
		return err
	}
	if err := s.userRepo.UpdateMPIN(ctx, userID, string(hash)); err != nil {
		return err
	}
	return s.userRepo.UpdateStatus(ctx, userID, model.UserStatusActive)
}

func (s *authService) LoginWithMPIN(ctx context.Context, mobile, mpin, deviceID string) (*model.AuthResponse, error) {
	user, err := s.userRepo.FindByMobile(ctx, mobile)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, ErrUserNotFound
	}

	lockKey := fmt.Sprintf("mpin_lock:%s", user.ID.Hex())
	attemptKey := fmt.Sprintf("mpin_attempts:%s", user.ID.Hex())

	locked, _ := s.redis.Exists(ctx, lockKey).Result()
	if locked > 0 || user.Status == model.UserStatusLocked {
		return nil, ErrAccountLocked
	}

	if user.MPINHash == "" {
		return nil, ErrMPINNotSet
	}

	if err := bcrypt.CompareHashAndPassword([]byte(user.MPINHash), []byte(mpin)); err != nil {
		attempts, _ := s.redis.Incr(ctx, attemptKey).Result()
		s.redis.Expire(ctx, attemptKey, 15*time.Minute)
		if int(attempts) >= s.maxAttempts {
			s.redis.Set(ctx, lockKey, "1", 30*time.Minute)
			_ = s.userRepo.UpdateStatus(ctx, user.ID, model.UserStatusLocked)
			return nil, ErrAccountLocked
		}
		return nil, ErrInvalidMPIN
	}

	s.redis.Del(ctx, attemptKey)
	return s.generateTokenPair(ctx, user, deviceID)
}

func (s *authService) LoginWithBiometric(ctx context.Context, deviceID, secureKey string) (*model.AuthResponse, error) {
	device, err := s.deviceRepo.FindByDeviceAndKey(ctx, deviceID, secureKey)
	if err != nil {
		return nil, err
	}
	if device == nil {
		return nil, ErrInvalidDevice
	}
	user, err := s.userRepo.FindByID(ctx, device.UserID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, ErrUserNotFound
	}
	return s.generateTokenPair(ctx, user, deviceID)
}

func (s *authService) RefreshToken(ctx context.Context, refreshToken string) (*model.AuthResponse, error) {
	claims, err := s.jwtSvc.ValidateToken(refreshToken)
	if err != nil {
		return nil, ErrInvalidSession
	}
	if claims.Type != "refresh" {
		return nil, ErrInvalidSession
	}
	session, err := s.sessionRepo.FindByRefreshToken(ctx, refreshToken)
	if err != nil {
		return nil, err
	}
	if session == nil {
		return nil, ErrInvalidSession
	}
	userID, err := bson.ObjectIDFromHex(claims.UserID)
	if err != nil {
		return nil, ErrInvalidSession
	}
	user, err := s.userRepo.FindByID(ctx, userID)
	if err != nil {
		return nil, err
	}
	if user == nil {
		return nil, ErrUserNotFound
	}
	_ = s.sessionRepo.Revoke(ctx, session.ID)
	return s.generateTokenPair(ctx, user, session.DeviceID)
}

func (s *authService) Logout(ctx context.Context, userID bson.ObjectID) error {
	return s.sessionRepo.RevokeAllForUser(ctx, userID)
}

func (s *authService) BindDevice(ctx context.Context, userID bson.ObjectID, req *model.BindDeviceRequest) error {
	device := &model.Device{
		UserID:     userID,
		DeviceID:   req.DeviceID,
		DeviceName: req.DeviceName,
		Platform:   req.Platform,
		SecureKey:  req.SecureKey,
		Trusted:    true,
	}
	return s.deviceRepo.Upsert(ctx, device)
}

func (s *authService) generateTokenPair(ctx context.Context, user *model.User, deviceID string) (*model.AuthResponse, error) {
	accessToken, err := s.jwtSvc.GenerateAccessToken(user.ID, user.Mobile)
	if err != nil {
		return nil, err
	}
	refreshToken, err := s.jwtSvc.GenerateRefreshToken(user.ID, user.Mobile)
	if err != nil {
		return nil, err
	}
	session := &model.Session{
		UserID:       user.ID,
		RefreshToken: refreshToken,
		DeviceID:     deviceID,
		ExpiresAt:    time.Now().AddDate(0, 0, s.refreshExp),
	}
	if err := s.sessionRepo.Create(ctx, session); err != nil {
		return nil, err
	}
	return &model.AuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    s.accessExp * 60,
	}, nil
}
