package uauth

import (
	"github.com/dunv/mongo"
	mgo "gopkg.in/mgo.v2"
	"gopkg.in/mgo.v2/bson"
)

// RolesCollection is the name of the collection in mongo
const RolesCollection = "roles"

func roleModelIndex() mgo.Index {
	return mgo.Index{
		Key:        []string{"name"},
		Unique:     true,
		DropDups:   true,
		Background: true,
		Sparse:     true,
	}
}

// RoleService datastructure
type RoleService struct {
	collection *mgo.Collection
}

// NewRoleService for creating a RoleService
func NewRoleService(db *mongo.DbSession) *RoleService {
	collection := db.GetCollection(RolesCollection)
	collection.EnsureIndex(roleModelIndex())
	return &RoleService{collection}
}

// GetMultipleByName from mongoDB
func (roleService *RoleService) GetMultipleByName(roleNames []string) ([]Role, error) {
	var results []Role

	queryParts := []bson.M{}
	for _, roleName := range roleNames {
		queryParts = append(queryParts, bson.M{"name": roleName})
	}

	err := roleService.collection.Find(bson.M{"$or": queryParts}).All(&results)
	return results, err
}

// GetAllRoles from mongoDB
func (roleService *RoleService) GetAllRoles() (*[]Role, error) {
	results := &[]Role{}
	err := roleService.collection.Find(bson.M{}).All(results)
	return results, err
}

// CreateRole creates a user in the db
func (roleService *RoleService) CreateRole(role *Role) error {
	role.GenerateID()
	return roleService.collection.Insert(role)
}
