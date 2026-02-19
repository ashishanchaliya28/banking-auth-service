package repository

import (
	"context"
	"time"

	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

func CreateIndexes(db *mongo.Database) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	_, err := db.Collection("users").Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: bson.D{{Key: "mobile", Value: 1}}, Options: options.Index().SetUnique(true)},
		{Keys: bson.D{{Key: "status", Value: 1}}},
	})
	if err != nil {
		return err
	}

	_, err = db.Collection("otp_logs").Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: bson.D{{Key: "mobile", Value: 1}, {Key: "verified", Value: 1}}},
		{Keys: bson.D{{Key: "expires_at", Value: 1}}, Options: options.Index().SetExpireAfterSeconds(0)},
	})
	if err != nil {
		return err
	}

	_, err = db.Collection("devices").Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: bson.D{{Key: "user_id", Value: 1}, {Key: "device_id", Value: 1}}, Options: options.Index().SetUnique(true)},
	})
	if err != nil {
		return err
	}

	_, err = db.Collection("sessions").Indexes().CreateMany(ctx, []mongo.IndexModel{
		{Keys: bson.D{{Key: "refresh_token", Value: 1}}, Options: options.Index().SetUnique(true)},
		{Keys: bson.D{{Key: "user_id", Value: 1}}},
		{Keys: bson.D{{Key: "expires_at", Value: 1}}, Options: options.Index().SetExpireAfterSeconds(0)},
	})
	return err
}
