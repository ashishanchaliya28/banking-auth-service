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

type DeviceRepository interface {
	FindByUserAndDevice(ctx context.Context, userID bson.ObjectID, deviceID string) (*model.Device, error)
	FindByDeviceAndKey(ctx context.Context, deviceID, secureKey string) (*model.Device, error)
	Upsert(ctx context.Context, device *model.Device) error
}

type deviceRepo struct {
	col *mongo.Collection
}

func NewDeviceRepository(db *mongo.Database) DeviceRepository {
	return &deviceRepo{col: db.Collection("devices")}
}

func (r *deviceRepo) FindByUserAndDevice(ctx context.Context, userID bson.ObjectID, deviceID string) (*model.Device, error) {
	var device model.Device
	err := r.col.FindOne(ctx, bson.M{"user_id": userID, "device_id": deviceID}).Decode(&device)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, nil
	}
	return &device, err
}

func (r *deviceRepo) FindByDeviceAndKey(ctx context.Context, deviceID, secureKey string) (*model.Device, error) {
	var device model.Device
	err := r.col.FindOne(ctx, bson.M{"device_id": deviceID, "secure_key": secureKey, "trusted": true}).Decode(&device)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, nil
	}
	return &device, err
}

func (r *deviceRepo) Upsert(ctx context.Context, device *model.Device) error {
	now := time.Now()
	device.UpdatedAt = now
	if device.ID.IsZero() {
		device.ID = bson.NewObjectID()
		device.CreatedAt = now
	}
	_, err := r.col.UpdateOne(ctx,
		bson.M{"user_id": device.UserID, "device_id": device.DeviceID},
		bson.M{"$set": device},
		options.Update().SetUpsert(true),
	)
	return err
}
