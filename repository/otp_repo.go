package repository

import (
	"context"
	"errors"
	"time"

	"github.com/banking-superapp/auth-service/model"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
	"go.mongodb.org/mongo-driver/v2/mongo/options"
)

type OTPRepository interface {
	Save(ctx context.Context, log *model.OTPLog) error
	FindLatest(ctx context.Context, mobile string) (*model.OTPLog, error)
	MarkVerified(ctx context.Context, id bson.ObjectID) error
}

type otpRepo struct {
	col *mongo.Collection
}

func NewOTPRepository(db *mongo.Database) OTPRepository {
	return &otpRepo{col: db.Collection("otp_logs")}
}

func (r *otpRepo) Save(ctx context.Context, log *model.OTPLog) error {
	log.ID = bson.NewObjectID()
	log.CreatedAt = time.Now()
	_, err := r.col.InsertOne(ctx, log)
	return err
}

func (r *otpRepo) FindLatest(ctx context.Context, mobile string) (*model.OTPLog, error) {
	var log model.OTPLog
	err := r.col.FindOne(ctx,
		bson.M{"mobile": mobile, "verified": false, "expires_at": bson.M{"$gt": time.Now()}},
		options.FindOne().SetSort(bson.D{{Key: "created_at", Value: -1}}),
	).Decode(&log)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, nil
	}
	return &log, err
}

func (r *otpRepo) MarkVerified(ctx context.Context, id bson.ObjectID) error {
	_, err := r.col.UpdateOne(ctx,
		bson.M{"_id": id},
		bson.M{"$set": bson.M{"verified": true}},
	)
	return err
}
