package uauth

import (
	"context"

	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
)

type RoleService struct {
	Collection *mongo.Collection
}

// NewRoleService for creating a RoleService
func NewRoleService(db *mongo.Client, dbName string) *RoleService {
	return &RoleService{
		Collection: db.Database(dbName).Collection("roles"),
	}
}

// GetMultipleByName from mongoDB
func (s *RoleService) GetMultipleByName(roleNames []string) (*[]Role, error) {
	queryParts := []bson.M{}
	for _, roleName := range roleNames {
		queryParts = append(queryParts, bson.M{"name": roleName})
	}
	return cursorToRoles(s.Collection.Find(context.Background(), bson.D{{Key: "$or", Value: queryParts}}))
}

// GetAllRoles from mongoDB
func (s *RoleService) List() (*[]Role, error) {
	return cursorToRoles(s.Collection.Find(context.Background(), bson.D{}))
}

// CreateRole creates a user in the db
func (s *RoleService) CreateRole(role *Role) error {
	_, err := s.Collection.InsertOne(context.Background(), role)
	return err
}

func cursorToRoles(cur *mongo.Cursor, err error) (*[]Role, error) {
	if err != nil {
		return nil, err
	}
	var results []Role
	defer cur.Close(context.Background())
	for cur.Next(context.Background()) {
		var result Role
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
