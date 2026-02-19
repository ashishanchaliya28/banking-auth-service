package config

import "github.com/spf13/viper"

type Config struct {
	Port               string
	MongoAtlasURI      string
	RedisURL           string
	JWTPrivateKey      string
	JWTPublicKey       string
	ServiceName        string
	LogLevel           string
	OTPExpiryMinutes   int
	MPINMaxAttempts    int
	AccessTokenExpiry  int
	RefreshTokenExpiry int
}

func Load() *Config {
	viper.AutomaticEnv()
	viper.SetDefault("PORT", "8080")
	viper.SetDefault("OTP_EXPIRY_MINUTES", 10)
	viper.SetDefault("MPIN_MAX_ATTEMPTS", 5)
	viper.SetDefault("ACCESS_TOKEN_EXPIRY", 15)
	viper.SetDefault("REFRESH_TOKEN_EXPIRY", 30)
	viper.SetDefault("LOG_LEVEL", "info")

	return &Config{
		Port:               viper.GetString("PORT"),
		MongoAtlasURI:      viper.GetString("MONGODB_ATLAS_URI"),
		RedisURL:           viper.GetString("REDIS_URL"),
		JWTPrivateKey:      viper.GetString("JWT_PRIVATE_KEY"),
		JWTPublicKey:       viper.GetString("JWT_PUBLIC_KEY"),
		ServiceName:        viper.GetString("SERVICE_NAME"),
		LogLevel:           viper.GetString("LOG_LEVEL"),
		OTPExpiryMinutes:   viper.GetInt("OTP_EXPIRY_MINUTES"),
		MPINMaxAttempts:    viper.GetInt("MPIN_MAX_ATTEMPTS"),
		AccessTokenExpiry:  viper.GetInt("ACCESS_TOKEN_EXPIRY"),
		RefreshTokenExpiry: viper.GetInt("REFRESH_TOKEN_EXPIRY"),
	}
}
