package permissions

// Permission type
type Permission string

const (
	// CanReadUsers Permission for reading all users
	CanReadUsers Permission = "canReadUsers"
	// CanCreateUsers Permission for creating users
	CanCreateUsers Permission = "canCreateUsers"
	// CanUpdateUsers Permission for updating users
	CanUpdateUsers Permission = "canUpdateUsers"
	// CanDeleteUsers Permission for deleting users
	CanDeleteUsers Permission = "canDeleteUsers"
)
