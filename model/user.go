package model

import (
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
)

type UserStatus string

const (
	UserStatusActive  UserStatus = "active"
	UserStatusLocked  UserStatus = "locked"
	UserStatusPending UserStatus = "pending"
)

type User struct {
	ID        bson.ObjectID `bson:"_id,omitempty" json:"id"`
	Mobile    string        `bson:"mobile" json:"mobile"`
	MPINHash  string        `bson:"mpin_hash" json:"-"`
	Status    UserStatus    `bson:"status" json:"status"`
	CreatedAt time.Time     `bson:"created_at" json:"created_at"`
	UpdatedAt time.Time     `bson:"updated_at" json:"updated_at"`
	DeletedAt *time.Time    `bson:"deleted_at,omitempty" json:"-"`
}

type OTPLog struct {
	ID        bson.ObjectID `bson:"_id,omitempty" json:"id"`
	Mobile    string        `bson:"mobile" json:"mobile"`
	OTP       string        `bson:"otp" json:"-"`
	ExpiresAt time.Time     `bson:"expires_at" json:"expires_at"`
	Verified  bool          `bson:"verified" json:"verified"`
	CreatedAt time.Time     `bson:"created_at" json:"created_at"`
}

type Device struct {
	ID         bson.ObjectID `bson:"_id,omitempty" json:"id"`
	UserID     bson.ObjectID `bson:"user_id" json:"user_id"`
	DeviceID   string        `bson:"device_id" json:"device_id"`
	DeviceName string        `bson:"device_name" json:"device_name"`
	Platform   string        `bson:"platform" json:"platform"`
	SecureKey  string        `bson:"secure_key" json:"-"`
	Trusted    bool          `bson:"trusted" json:"trusted"`
	CreatedAt  time.Time     `bson:"created_at" json:"created_at"`
	UpdatedAt  time.Time     `bson:"updated_at" json:"updated_at"`
}

type Session struct {
	ID           bson.ObjectID `bson:"_id,omitempty" json:"id"`
	UserID       bson.ObjectID `bson:"user_id" json:"user_id"`
	RefreshToken string        `bson:"refresh_token" json:"-"`
	DeviceID     string        `bson:"device_id" json:"device_id"`
	ExpiresAt    time.Time     `bson:"expires_at" json:"expires_at"`
	Revoked      bool          `bson:"revoked" json:"revoked"`
	CreatedAt    time.Time     `bson:"created_at" json:"created_at"`
}

type SendOTPRequest struct {
	Mobile string `json:"mobile"`
}

type VerifyOTPRequest struct {
	Mobile string `json:"mobile"`
	OTP    string `json:"otp"`
}

type SetMPINRequest struct {
	MPIN string `json:"mpin"`
}

type LoginMPINRequest struct {
	Mobile   string `json:"mobile"`
	MPIN     string `json:"mpin"`
	DeviceID string `json:"device_id"`
}

type BiometricLoginRequest struct {
	DeviceID  string `json:"device_id"`
	SecureKey string `json:"secure_key"`
}

type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type BindDeviceRequest struct {
	DeviceID   string `json:"device_id"`
	DeviceName string `json:"device_name"`
	Platform   string `json:"platform"`
	SecureKey  string `json:"secure_key"`
}

type AuthResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"`
}
