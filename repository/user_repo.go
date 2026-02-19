package repository

import (
	"context"
	"errors"
	"time"

	"github.com/banking-superapp/auth-service/model"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

type UserRepository interface {
	FindByMobile(ctx context.Context, mobile string) (*model.User, error)
	FindByID(ctx context.Context, id bson.ObjectID) (*model.User, error)
	Create(ctx context.Context, user *model.User) error
	UpdateMPIN(ctx context.Context, userID bson.ObjectID, mpinHash string) error
	UpdateStatus(ctx context.Context, userID bson.ObjectID, status model.UserStatus) error
}

type userRepo struct {
	col *mongo.Collection
}

func NewUserRepository(db *mongo.Database) UserRepository {
	return &userRepo{col: db.Collection("users")}
}

func (r *userRepo) FindByMobile(ctx context.Context, mobile string) (*model.User, error) {
	var user model.User
	err := r.col.FindOne(ctx, bson.M{"mobile": mobile, "deleted_at": nil}).Decode(&user)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, nil
	}
	return &user, err
}

func (r *userRepo) FindByID(ctx context.Context, id bson.ObjectID) (*model.User, error) {
	var user model.User
	err := r.col.FindOne(ctx, bson.M{"_id": id, "deleted_at": nil}).Decode(&user)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, nil
	}
	return &user, err
}

func (r *userRepo) Create(ctx context.Context, user *model.User) error {
	user.ID = bson.NewObjectID()
	user.CreatedAt = time.Now()
	user.UpdatedAt = time.Now()
	_, err := r.col.InsertOne(ctx, user)
	return err
}

func (r *userRepo) UpdateMPIN(ctx context.Context, userID bson.ObjectID, mpinHash string) error {
	_, err := r.col.UpdateOne(ctx,
		bson.M{"_id": userID},
		bson.M{"$set": bson.M{"mpin_hash": mpinHash, "updated_at": time.Now()}},
	)
	return err
}

func (r *userRepo) UpdateStatus(ctx context.Context, userID bson.ObjectID, status model.UserStatus) error {
	_, err := r.col.UpdateOne(ctx,
		bson.M{"_id": userID},
		bson.M{"$set": bson.M{"status": status, "updated_at": time.Now()}},
	)
	return err
}
