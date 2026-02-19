package repository

import (
	"context"
	"errors"
	"time"

	"github.com/banking-superapp/auth-service/model"
	"go.mongodb.org/mongo-driver/v2/bson"
	"go.mongodb.org/mongo-driver/v2/mongo"
)

type SessionRepository interface {
	Create(ctx context.Context, session *model.Session) error
	FindByRefreshToken(ctx context.Context, token string) (*model.Session, error)
	Revoke(ctx context.Context, id bson.ObjectID) error
	RevokeAllForUser(ctx context.Context, userID bson.ObjectID) error
}

type sessionRepo struct {
	col *mongo.Collection
}

func NewSessionRepository(db *mongo.Database) SessionRepository {
	return &sessionRepo{col: db.Collection("sessions")}
}

func (r *sessionRepo) Create(ctx context.Context, session *model.Session) error {
	session.ID = bson.NewObjectID()
	session.CreatedAt = time.Now()
	_, err := r.col.InsertOne(ctx, session)
	return err
}

func (r *sessionRepo) FindByRefreshToken(ctx context.Context, token string) (*model.Session, error) {
	var session model.Session
	err := r.col.FindOne(ctx, bson.M{
		"refresh_token": token,
		"revoked":       false,
		"expires_at":    bson.M{"$gt": time.Now()},
	}).Decode(&session)
	if errors.Is(err, mongo.ErrNoDocuments) {
		return nil, nil
	}
	return &session, err
}

func (r *sessionRepo) Revoke(ctx context.Context, id bson.ObjectID) error {
	_, err := r.col.UpdateOne(ctx,
		bson.M{"_id": id},
		bson.M{"$set": bson.M{"revoked": true}},
	)
	return err
}

func (r *sessionRepo) RevokeAllForUser(ctx context.Context, userID bson.ObjectID) error {
	_, err := r.col.UpdateMany(ctx,
		bson.M{"user_id": userID, "revoked": false},
		bson.M{"$set": bson.M{"revoked": true}},
	)
	return err
}
