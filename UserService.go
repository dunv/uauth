package uauth

import (
	"context"
	"fmt"

	"github.com/dunv/uhelpers"
	"github.com/dunv/umongo"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

// UserService datastructure
type UserService struct {
	umongo.ModelService
	roleService *RoleService
}

// NewUserService for creating a UserService
func NewUserService(db *mongo.Client, dbName string) *UserService {
	return &UserService{
		roleService: NewRoleService(db, dbName),
		ModelService: umongo.NewModelService(db, dbName, "users", []mongo.IndexModel{
			{
				Keys: bson.M{"userName": 1},
				Options: &options.IndexOptions{
					Name:       uhelpers.PtrToString("userName_1"),
					Background: uhelpers.PtrToBool(true),
					Unique:     uhelpers.PtrToBool(true),
				},
			},
			{
				Keys: bson.D{bson.E{Key: "userName", Value: 1}, bson.E{Key: "refreshTokens", Value: 1}},
				Options: &options.IndexOptions{
					Name:       uhelpers.PtrToString("userName_refreshTokens_1"),
					Background: uhelpers.PtrToBool(true),
					Unique:     uhelpers.PtrToBool(true),
				},
			},
		}),
	}
}

// CreateUser creates a user in the db
func (s *UserService) CreateUser(user *User) error {
	newObjectID := primitive.NewObjectID()
	user.ID = &newObjectID
	_, err := s.Col.InsertOne(context.Background(), user)
	return err
}

// GetByUserName from mongoDB
func (s *UserService) getRawByUserName(userName string) (*User, error) {
	user := &User{}
	res := s.Col.FindOne(context.Background(), bson.M{"userName": userName})
	if err := res.Decode(user); err != nil {
		return nil, fmt.Errorf("Could not decode (%s)", err)
	}
	return user, nil
}

// GetByUserName from mongoDB
func (s *UserService) getRawByUserID(userID primitive.ObjectID) (*User, error) {
	user := &User{}
	res := s.Col.FindOne(context.Background(), bson.M{"_id": userID})
	if err := res.Decode(user); err != nil {
		return nil, fmt.Errorf("Could not decode (%s)", err)
	}
	return user, nil
}

func (s *UserService) GetUIUserByUserNameAndCheckPassword(userName string, plainTextPassword string) (*User, error) {
	user, err := s.getRawByUserName(userName)
	if err != nil {
		return nil, err
	}

	if !user.CheckPassword(plainTextPassword) {
		return nil, ErrInvalidUser
	}

	roleDict, err := s.roleService.GetMultipleByName(*user.Roles)
	if err != nil {
		return nil, err
	}
	uiUser, err := user.CleanForUI(roleDict)
	if err != nil {
		return nil, err
	}
	return uiUser, nil
}

func (s *UserService) GetUiUserByUserID(ID primitive.ObjectID) (*User, error) {
	user, err := s.getRawByUserID(ID)
	if err != nil {
		return nil, err
	}
	roleDict, err := s.roleService.GetMultipleByName(*user.Roles)
	if err != nil {
		return nil, err
	}
	uiUser, err := user.CleanForUI(roleDict)
	if err != nil {
		return nil, err
	}
	return uiUser, nil
}

// GetUiUserByUserName from mongoDB
func (s *UserService) GetUiUserByUserName(userName string) (*User, error) {
	user, err := s.getRawByUserName(userName)
	if err != nil {
		return nil, err
	}
	roleDict, err := s.roleService.GetMultipleByName(*user.Roles)
	if err != nil {
		return nil, err
	}
	uiUser, err := user.CleanForUI(roleDict)
	if err != nil {
		return nil, err
	}
	return uiUser, nil
}

func (s *UserService) AddRefreshToken(userName string, refreshToken string, ctx context.Context) error {
	_, err := s.Col.UpdateOne(ctx,
		bson.M{"userName": userName},
		bson.M{"$push": bson.M{"refreshTokens": refreshToken}},
	)
	return err
}

func (s *UserService) RemoveRefreshToken(userName string, refreshToken string, ctx context.Context) error {
	_, err := s.Col.UpdateOne(ctx,
		bson.M{"userName": userName, "refreshTokens": refreshToken},
		bson.M{"$pull": bson.M{"refreshTokens": refreshToken}},
	)
	return err
}

func (s *UserService) FindRefreshToken(userName string, refreshToken string, ctx context.Context) error {
	res := s.Col.FindOne(ctx, bson.M{"userName": userName, "refreshTokens": refreshToken})
	if res.Err() != nil {
		return res.Err()
	}
	return nil
}

func (s *UserService) ListRefreshTokens(userName string, ctx context.Context) ([]string, error) {
	res := s.Col.FindOne(ctx, bson.M{"userName": userName}, options.FindOne().SetProjection(bson.M{"refreshTokens": 1}))
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

func (s *UserService) DeleteExpiredRefreshTokens(userName string, ctx context.Context) error {
	cfg, err := ConfigFromContext(ctx)
	if err != nil {
		return err
	}

	tokens, err := s.ListRefreshTokens(userName, ctx)
	if err != nil {
		return err
	}

	// Go through all tokens, check if they are valid (if they are expired, they will be invalid automatically,
	// currently we do not issue tokens that start being valid in the future)
	for _, refreshToken := range tokens {
		_, _, err := ParseRefreshToken(refreshToken, cfg)
		if err != nil {
			if err := s.RemoveRefreshToken(userName, refreshToken, ctx); err != nil {
				return err
			}
		}
	}

	return nil
}

func (s *UserService) Get(ID primitive.ObjectID) (*User, error) {
	user := &User{}
	res := s.Col.FindOne(context.Background(), bson.M{"_id": ID})
	if err := res.Decode(user); err != nil {
		return nil, err
	}
	return user, nil
}

func (s *UserService) List() (*[]User, error) {
	return cursorToUsers(s.Col.Find(context.Background(), bson.M{}))
}

func (s *UserService) Update(user User) error {
	res := s.Col.FindOneAndUpdate(
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
	_, err := s.Col.DeleteOne(
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
		results = append(results, result)
	}
	if err := cur.Err(); err != nil {
		return nil, err
	}
	return &results, nil
}

func (s *UserService) UpdateAdditionalAttributes(userName string, additionalAttributes interface{}, ctx context.Context) error {
	res := s.Col.FindOneAndUpdate(
		ctx,
		bson.M{"userName": userName},
		bson.M{"$set": bson.M{"additionalAttributes": additionalAttributes}},
	)

	return res.Err()
}
