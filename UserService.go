package uauth

import (
	"context"

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
		Database:   userDB,
		Collection: "users",
	}
}

// CreateUser creates a user in the db
func (s *UserService) CreateUser(user *User) error {
	newObjectID := primitive.NewObjectID()
	user.ID = &newObjectID
	_, err := s.Client.Database(s.Database).Collection(s.Collection).InsertOne(context.Background(), user)
	return err
}

// GetByUserName from mongoDB
func (s *UserService) GetByUserName(userName string) (*User, error) {
	user := &User{}
	res := s.Client.Database(s.Database).Collection(s.Collection).FindOne(context.Background(), bson.D{{"userName", userName}})
	if err := res.Decode(user); err != nil {
		return nil, err
	}
	return user, nil
}

// Get <-
func (s *UserService) Get(ID primitive.ObjectID) (*User, error) {
	user := &User{}
	res := s.Client.Database(s.Database).Collection(s.Collection).FindOne(context.Background(), bson.D{{"_id", ID}})
	if err := res.Decode(user); err != nil {
		return nil, err
	}
	return user, nil
}

// List <-
func (s *UserService) List() (*[]User, error) {
	return cursorToUsers(s.Client.Database(s.Database).Collection(s.Collection).Find(context.Background(), bson.D{}))
}

// Update <-
func (s *UserService) Update(userID primitive.ObjectID, user UpdateUserModel) error {
	res := s.Client.Database(s.Database).Collection(s.Collection).FindOneAndUpdate(
		context.Background(),
		bson.D{{
			"_id", userID,
		}},
		bson.D{{
			"$set", user,
		}})

	return res.Err()
}

// Delete <-
func (s *UserService) Delete(userID primitive.ObjectID) error {
	_, err := s.Client.Database(s.Database).Collection(s.Collection).DeleteOne(
		context.Background(),
		bson.D{{
			"_id", userID,
		}})
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
			return nil, err
		}
		results = append(results, result)
	}
	if err := cur.Err(); err != nil {
		return nil, err
	}
	return &results, nil
}
