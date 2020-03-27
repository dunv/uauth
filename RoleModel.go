package uauth

type Role struct {
	Name        string       `bson:"name" json:"name"`
	Permissions []Permission `bson:"permissions" json:"permissions"`
}
