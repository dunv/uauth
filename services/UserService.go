package services

import (
	"context"
	"fmt"

	"github.com/dunv/uauth"
	"github.com/dunv/uauth/interfaces"
	"github.com/dunv/uauth/models"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
)

// UserService datastructure
type UserService struct {
	Client     *mongo.Client
	Database   string
	Collection string
}

// NewUserService for creating a UserService
func NewUserService(db *mongo.Client) *UserService {
	return &UserService{
		Client:     db,
		Database:   uauth.Config().UserDbName,
		Collection: "users",
	}
}

// CreateUser creates a user in the db
func (s *UserService) CreateUser(user *models.User) error {
	newObjectID := primitive.NewObjectID()
	user.ID = &newObjectID
	_, err := s.Client.Database(s.Database).Collection(s.Collection).InsertOne(context.Background(), user)
	return err
}

// GetByUserName from mongoDB
func (s *UserService) GetByUserName(userName string) (*models.User, error) {
	user := &models.User{}
	res := s.Client.Database(s.Database).Collection(s.Collection).FindOne(context.Background(), bson.D{{Key: "userName", Value: userName}})
	if err := res.Decode(user); err != nil {
		return nil, fmt.Errorf("Could not decode (%s)", err)
	}
	err := user.UnmarshalAdditionalAttributes()
	if err != nil {
		return nil, fmt.Errorf("Could not marshal additional attributes (%s)", err)
	}
	return user, nil
}

func (s *UserService) Get(ID primitive.ObjectID) (*models.User, error) {
	user := &models.User{}
	res := s.Client.Database(s.Database).Collection(s.Collection).FindOne(context.Background(), bson.D{{Key: "_id", Value: ID}})
	if err := res.Decode(user); err != nil {
		return nil, err
	}
	err := user.UnmarshalAdditionalAttributes()
	if err != nil {
		return nil, fmt.Errorf("Could not marshal additional attributes (%s)", err)
	}
	return user, nil
}

func (s *UserService) List() (*[]models.User, error) {
	return cursorToUsers(s.Client.Database(s.Database).Collection(s.Collection).Find(context.Background(), bson.D{}))
}

func (s *UserService) Update(user models.User) error {
	res := s.Client.Database(s.Database).Collection(s.Collection).FindOneAndUpdate(
		context.Background(),
		bson.D{{Key: "_id", Value: user.ID}},
		bson.D{{Key: "$set", Value: models.User{
			ID:        user.ID,
			UserName:  user.UserName,
			FirstName: user.FirstName,
			LastName:  user.LastName,
			Password:  user.Password,
			Roles:     user.Roles,
		}}})

	return res.Err()
}

func (s *UserService) Delete(userID primitive.ObjectID) error {
	_, err := s.Client.Database(s.Database).Collection(s.Collection).DeleteOne(
		context.Background(),
		bson.D{{Key: "_id", Value: userID}})
	return err
}

func cursorToUsers(cur *mongo.Cursor, err error) (*[]models.User, error) {
	if err != nil {
		return nil, err
	}
	var results []models.User
	defer cur.Close(context.Background())
	for cur.Next(context.Background()) {
		var result models.User
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

func (s *UserService) UpdateAdditionalAttributes(userName string, additionalAttributes interfaces.AdditionalUserAttributesInterface) error {
	res := s.Client.Database(s.Database).Collection(s.Collection).FindOneAndUpdate(
		context.Background(),
		bson.D{{Key: "userName", Value: userName}},
		bson.D{{Key: "$set", Value: bson.D{
			{Key: "additionalAttributes", Value: additionalAttributes},
		}}})

	return res.Err()
}
