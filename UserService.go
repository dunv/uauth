package uauth

import (
	"context"
	"fmt"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// UserService datastructure
type UserService struct {
	Collection *mongo.Collection
}

// NewUserService for creating a UserService
func NewUserService(db *mongo.Client, dbName string) *UserService {
	return &UserService{
		Collection: db.Database(dbName).Collection("users"),
	}
}

// CreateUser creates a user in the db
func (s *UserService) CreateUser(user *User) error {
	newObjectID := primitive.NewObjectID()
	user.ID = &newObjectID
	_, err := s.Collection.InsertOne(context.Background(), user)
	return err
}

// GetByUserName from mongoDB
func (s *UserService) GetByUserName(userName string) (*User, error) {
	user := &User{}
	res := s.Collection.FindOne(context.Background(), bson.M{"userName": userName})
	if err := res.Decode(user); err != nil {
		return nil, fmt.Errorf("Could not decode (%s)", err)
	}
	err := user.UnmarshalAdditionalAttributes()
	if err != nil {
		return nil, fmt.Errorf("Could not marshal additional attributes (%s)", err)
	}
	return user, nil
}

func (s *UserService) AddRefreshToken(userName string, refreshToken string, ctx context.Context) error {
	_, err := s.Collection.UpdateOne(ctx,
		bson.M{"userName": userName},
		bson.M{"$push": bson.M{"refreshTokens": refreshToken}},
	)
	return err
}

func (s *UserService) RemoveRefreshToken(userName string, refreshToken string, ctx context.Context) error {
	_, err := s.Collection.UpdateOne(ctx,
		bson.M{"userName": userName, "refreshTokens": refreshToken},
		bson.M{"$pull": bson.M{"refreshTokens": refreshToken}},
	)
	return err
}

func (s *UserService) FindRefreshToken(userName string, refreshToken string, ctx context.Context) error {
	res := s.Collection.FindOne(ctx, bson.M{"userName": userName, "refreshTokens": refreshToken})
	if res.Err() != nil {
		return res.Err()
	}
	return nil
}

func (s *UserService) ListRefreshTokens(userName string, ctx context.Context) ([]string, error) {
	res := s.Collection.FindOne(ctx, bson.M{"userName": userName}, options.FindOne().SetProjection(bson.M{"refreshTokens": 1}))
	if res.Err() != nil {
		return nil, res.Err()
	}
	userModel := User{}
	err := res.Decode(&userModel)
	if err != nil {
		return nil, err
	}

	if userModel.RefreshTokens == nil {
		return []string{}, nil
	}

	return *userModel.RefreshTokens, nil
}

func (s *UserService) Get(ID primitive.ObjectID) (*User, error) {
	user := &User{}
	res := s.Collection.FindOne(context.Background(), bson.M{"_id": ID})
	if err := res.Decode(user); err != nil {
		return nil, err
	}
	err := user.UnmarshalAdditionalAttributes()
	if err != nil {
		return nil, fmt.Errorf("Could not marshal additional attributes (%s)", err)
	}
	return user, nil
}

func (s *UserService) List() (*[]User, error) {
	return cursorToUsers(s.Collection.Find(context.Background(), bson.M{}))
}

func (s *UserService) Update(user User) error {
	res := s.Collection.FindOneAndUpdate(
		context.Background(),
		bson.M{"_id": user.ID},
		bson.M{"$set": User{
			ID:        user.ID,
			UserName:  user.UserName,
			FirstName: user.FirstName,
			LastName:  user.LastName,
			Password:  user.Password,
			Roles:     user.Roles,
		}})

	return res.Err()
}

func (s *UserService) Delete(userID primitive.ObjectID) error {
	_, err := s.Collection.DeleteOne(
		context.Background(),
		bson.M{"_id": userID})
	return err
}

func cursorToUsers(cur *mongo.Cursor, err error) (*[]User, error) {
	if err != nil {
		return nil, err
	}
	var results []User
	defer cur.Close(context.Background())
	for cur.Next(context.Background()) {
		var result User
		err := cur.Decode(&result)
		if err != nil {
			return nil, fmt.Errorf("error marshalling decoding (%s)", err)
		}
		err = result.UnmarshalAdditionalAttributes()
		if err != nil {
			return nil, fmt.Errorf("error marshalling additional attributes (%s)", err)
		}
		results = append(results, result)
	}
	if err := cur.Err(); err != nil {
		return nil, err
	}
	return &results, nil
}

func (s *UserService) UpdateAdditionalAttributes(userName string, additionalAttributes AdditionalUserAttributesInterface) error {
	res := s.Collection.FindOneAndUpdate(
		context.Background(),
		bson.M{"userName": userName},
		bson.M{"$set": bson.M{"additionalAttributes": additionalAttributes}},
	)

	return res.Err()
}