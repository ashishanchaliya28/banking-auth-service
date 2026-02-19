package service

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"time"

	"github.com/banking-superapp/auth-service/model"
	"github.com/banking-superapp/auth-service/repository"
)

type OTPService interface {
	SendOTP(ctx context.Context, mobile string) error
	VerifyOTP(ctx context.Context, mobile, otp string) (bool, error)
}

type otpService struct {
	otpRepo       repository.OTPRepository
	expiryMinutes int
}

func NewOTPService(otpRepo repository.OTPRepository, expiryMinutes int) OTPService {
	return &otpService{otpRepo: otpRepo, expiryMinutes: expiryMinutes}
}

func (s *otpService) SendOTP(ctx context.Context, mobile string) error {
	otp, err := generateOTP(6)
	if err != nil {
		return err
	}

	log := &model.OTPLog{
		Mobile:    mobile,
		OTP:       otp,
		ExpiresAt: time.Now().Add(time.Duration(s.expiryMinutes) * time.Minute),
		Verified:  false,
	}

	if err := s.otpRepo.Save(ctx, log); err != nil {
		return err
	}

	// TODO: Integrate MSG91/Twilio for SMS delivery
	fmt.Printf("[OTP] Mobile: %s | OTP: %s\n", mobile, otp)
	return nil
}

func (s *otpService) VerifyOTP(ctx context.Context, mobile, otp string) (bool, error) {
	log, err := s.otpRepo.FindLatest(ctx, mobile)
	if err != nil {
		return false, err
	}
	if log == nil {
		return false, nil
	}
	if log.OTP != otp {
		return false, nil
	}
	if err := s.otpRepo.MarkVerified(ctx, log.ID); err != nil {
		return false, err
	}
	return true, nil
}

func generateOTP(length int) (string, error) {
	max := new(big.Int)
	max.Exp(big.NewInt(10), big.NewInt(int64(length)), nil)
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%0*d", length, n), nil
}
