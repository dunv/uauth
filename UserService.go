package uauth

import (
	"context"
	"encoding/json"
	"fmt"

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
	res := s.Client.Database(s.Database).Collection(s.Collection).FindOne(context.Background(), bson.D{{Key: "userName", Value: userName}})
	if err := res.Decode(user); err != nil {
		return nil, err
	}
	return user, nil
}

func (s *UserService) Get(ID primitive.ObjectID) (*User, error) {
	user := &User{}
	res := s.Client.Database(s.Database).Collection(s.Collection).FindOne(context.Background(), bson.D{{Key: "_id", Value: ID}})
	if err := res.Decode(user); err != nil {
		return nil, err
	}
	return user, nil
}

func (s *UserService) List() (*[]User, error) {
	return cursorToUsers(s.Client.Database(s.Database).Collection(s.Collection).Find(context.Background(), bson.D{}))
}

func (s *UserService) Update(user User) error {
	res := s.Client.Database(s.Database).Collection(s.Collection).FindOneAndUpdate(
		context.Background(),
		bson.D{{Key: "_id", Value: user.ID}},
		bson.D{{Key: "$set", Value: User{
			ID:        user.ID,
			UserName:  user.UserName,
			FirstName: user.FirstName,
			LastName:  user.LastName,
			Password:  user.Password,
			Roles:     user.Roles,
		}}})

	return res.Err()
}

func (s *UserService) GetAdditionalAttributes(userName string, additionalAttributes interface{}) error {
	res := s.Client.Database(s.Database).Collection(s.Collection).FindOne(context.Background(), bson.D{{Key: "userName", Value: userName}})
	if res.Err() != nil {
		return res.Err()
	}

	type tmpModel struct {
		AdditionlAttributes *json.RawMessage `bson:"additionalAttributes,omitempty" json:"additionalAttributes,omitempty"`
	}
	tmp := tmpModel{}
	if err := res.Decode(&tmp); err != nil {
		return fmt.Errorf("decoding issue %s", err)
	}

	if tmp.AdditionlAttributes != nil {
		err := json.Unmarshal(*tmp.AdditionlAttributes, &additionalAttributes)
		if err != nil {
			return fmt.Errorf("could not unmarshal %s", err)
		}
	}

	return nil

}

func (s *UserService) UpdateAdditionalAttributes(userName string, additionalAttributes interface{}) error {
	res := s.Client.Database(s.Database).Collection(s.Collection).FindOneAndUpdate(
		context.Background(),
		bson.D{{Key: "userName", Value: userName}},
		bson.D{{Key: "$set", Value: bson.D{
			{Key: "additionalAttributes", Value: additionalAttributes},
		}}})

	return res.Err()
}

func (s *UserService) Delete(userID primitive.ObjectID) error {
	_, err := s.Client.Database(s.Database).Collection(s.Collection).DeleteOne(
		context.Background(),
		bson.D{{Key: "_id", Value: userID}})
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
