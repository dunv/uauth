package services

import (
	"context"

	"github.com/dunv/uauth"
	"github.com/dunv/uauth/models"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

// RoleService datastructure
type RoleService struct {
	Client     *mongo.Client
	Database   string
	Collection string
}

// NewRoleService for creating a RoleService
func NewRoleService(db *mongo.Client) *RoleService {
	return &RoleService{
		Client:     db,
		Database:   uauth.Config().UserDbName,
		Collection: "roles",
	}
}

// GetMultipleByName from mongoDB
func (s *RoleService) GetMultipleByName(roleNames []string) (*[]models.Role, error) {
	queryParts := []bson.M{}
	for _, roleName := range roleNames {
		queryParts = append(queryParts, bson.M{"name": roleName})
	}
	return cursorToRoles(s.Client.Database(s.Database).Collection(s.Collection).Find(context.Background(), bson.D{{Key: "$or", Value: queryParts}}))
}

// GetAllRoles from mongoDB
func (s *RoleService) List() (*[]models.Role, error) {
	return cursorToRoles(s.Client.Database(s.Database).Collection(s.Collection).Find(context.Background(), bson.D{}))
}

// CreateRole creates a user in the db
func (s *RoleService) CreateRole(role *models.Role) error {
	_, err := s.Client.Database(s.Database).Collection(s.Collection).InsertOne(context.Background(), role)
	return err
}

func cursorToRoles(cur *mongo.Cursor, err error) (*[]models.Role, error) {
	if err != nil {
		return nil, err
	}
	var results []models.Role
	defer cur.Close(context.Background())
	for cur.Next(context.Background()) {
		var result models.Role
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
