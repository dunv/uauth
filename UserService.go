package uauth

import (
	"github.com/dunv/mongo"
	mgo "gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

// UsersCollection is the name of the collection in mongo
const UsersCollection = "users"

func userModelIndex() mgo.Index {
	return mgo.Index{
		Key:        []string{"userName"},
		Unique:     true,
		DropDups:   true,
		Background: true,
		Sparse:     true,
	}
}

// UserService datastructure
type UserService struct {
	collection *mgo.Collection
}

// CreateUser creates a user in the db
func (s *UserService) CreateUser(user *User) error {
	user.GenerateID()
	return s.collection.Insert(user)
}

// NewUserService for creating a UserService
func NewUserService(db *mongo.DbSession) *UserService {
	collection := db.GetCollection(UsersCollection)
	collection.EnsureIndex(userModelIndex())
	return &UserService{collection}
}

// GetByUserName from mongoDB
func (s *UserService) GetByUserName(userName string) (*User, error) {
	model := User{}
	err := s.collection.Find(bson.M{"userName": userName}).One(&model)
	return &model, err
}

// Get <-
func (s *UserService) Get(ID bson.ObjectId) (*User, error) {
	model := User{}
	err := s.collection.Find(bson.M{"_id": ID}).One(&model)
	return &model, err
}

// List <-
func (s *UserService) List() (*[]User, error) {
	results := &[]User{}
	err := s.collection.Find(bson.M{}).All(results)
	return results, err
}

// Update <-
func (s *UserService) Update(userID bson.ObjectId, user UpdateUserModel) error {
	return s.collection.Update(bson.M{"_id": userID}, bson.M{"$set": user})
}

// Delete <-
func (s *UserService) Delete(ID bson.ObjectId) error {
	return s.collection.Remove(bson.M{"_id": ID})
}
