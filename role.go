package goperm

import (
	"database/sql"
	"errors"
	"fmt"
	"github.com/jmoiron/sqlx"
	"github.com/roles/goperm/database"
	"regexp"
	"strings"
	"time"
)

const (
	MaxSlugLen        = 255
	MaxNameLen        = 255
	MaxDescriptionLen = 255
)

type PermissionSetType int

const (
	RolePermissionsSet PermissionSetType = 1 << iota
	UserPermissionsSet
	AllPermissionsSet
)

// if true, will allow the same permission to be set twice on the same user - one via a role, once directly
// this might desirable if you want a user to have a particular permission no matter what their roles they have,
// but it has the non-trivial side-effect that you have to remove the permission twice - once via the role
// and then again directly. It's best not to change this unless you have a use case that really needs it.
// NOTE : changing this from true to false must be done with care since duplicate permissions may already exist
// in the database.
const AllowDuplicatePermissions = false

var (
	ErrNoSuchRole             = errors.New("no such role")
	ErrRoleExistsOnUser       = errors.New("entity already has that role")
	ErrNoSuchPermission       = errors.New("no such permission")
	ErrPermissionExistsOnUser = errors.New("entity already has that permission")
)

// User should be replaced with your own user model
type User interface{}

// db should be set to your app's db instance
var db *sqlx.DB

///////////////////
// Roles
///////////////////

// The Role model (get it?)
type Role struct {
	Slug        string    `db:"role_slug"`
	Name        string    `db:"role_name"`
	Description string    `db:"role_description"`
	CreatedAt   time.Time `db:"created_at"`
	DeletedAt   time.Time `db:"deleted_at"`
}

// AllRoles returns a slice of all the roles in the db
func AllRoles() ([]Role, error) {

	var roles []Role
	err := db.Select(&roles, database.Role_SelectAll, time.Time{})
	if err != nil {
		return nil, err
	}

	return roles, nil
}

// AddNewRole adds a role to the db
func AddNewRole(slug, name, description string) (*Role, error) {

	isValid, err := isValidName(name)
	if err != nil {
		return nil, err
	}

	if !isValid {
		return nil, fmt.Errorf("'%s' is not a valid name", slug)
	}

	isValid, err = isValidSlug(slug, false)
	if err != nil {
		return nil, err
	}

	if !isValid {
		return nil, fmt.Errorf("'%s' is not a valid slug", slug)
	}

	isValid, err = isValidDescription(description)
	if err != nil {
		return nil, err
	}

	if !isValid {
		return nil, fmt.Errorf("'%s' is not a valid description", slug)
	}

	roleExists, _ := RoleExists(slug)
	if roleExists {
		return nil, fmt.Errorf("Cannot insert role. Role with slug '%s' already exists", slug)
	}

	r := Role{
		Slug:        slug,
		Name:        name,
		Description: description,
		CreatedAt:   time.Now(),
		DeletedAt:   time.Time{},
	}

	err = database.Exec1Row(db, database.Role_Insert, r.Slug, r.Name, r.Description, r.CreatedAt, r.DeletedAt)
	if err != nil {
		return nil, err
	}

	return &r, nil
}

// DeleteRole removes a role from the database. It does not remove any associated permissions since permissions can
// be added individually, and you might want them in another role in the future. Use DeletePermission if you want to
// delete a permission. Wildcard not allowed.
func DeleteRole(slug string) error {

	_, err := RoleBySlug(slug)
	if err == sql.ErrNoRows {
		return fmt.Errorf("Cannot delete role with slug '%s'. It doesn't exist.", slug)
	} else if err != nil {
		return err
	}

	// do any users have this role
	count, err := CountUsersForRole(slug)
	if err != nil {
		return err
	} else if count > 0 {
		return fmt.Errorf("There are %i users that still have this role. Remove the role from those users first.", count)
	}

	return database.Transact(db, []database.QueryExecFunc{
		database.TxExecFunc(database.RolePermission_Delete, time.Now(), slug, time.Time{}),
		database.TxExecFunc(database.Role_Delete, time.Time{}, slug),
	})
}

// AddRoleToUser adds an existing role to a user
func AddRoleToUser(userId interface{}, roleSlug string) error {

	isValid, err := isValidSlug(roleSlug, false)
	if err != nil {
		return err
	}

	if !isValid {
		return fmt.Errorf("Invalid role slug : '%s'. (wildcards are not permitted here)", roleSlug)
	}

	// look up the target role
	role, err := RoleBySlug(roleSlug)
	if err != nil {
		return err
	} else if role == nil {
		return fmt.Errorf("Failed to add role '%s' to user. That role does not exist.", roleSlug)
	}

	// look up all the roles the user currently has
	roles, err := RolesForUser(userId)
	if err != nil {
		return err
	}

	// calculate the unique set of permissions we need to add
	rolePermissions, err := uniquePermissionsForRole(*role, roles)
	if err != nil {
		return err
	}

	if !AllowDuplicatePermissions {
		// fail if there is an overlap between rolePermissions and
		userPermissions, err := PermissionsForUser(userId, UserPermissionsSet)
		if err != nil {
			return err
		}

		for _, v := range userPermissions {
			for _, x := range rolePermissions {
				if v.Slug == x.Slug {
					return fmt.Errorf("Can't add %s role: clash on existing user permission %s", roleSlug, x.Slug)
				}
			}
		}
	}

	err = doRolePermInsert(role, rolePermissions, userId)
	if err != nil {
		return err
	}

	return nil
}

// doRolePermInsert inserts a role and the set of permissions associated with it
func doRolePermInsert(role *Role, perms []Permission, userId interface{}) error {

	var now = time.Now()

	txFuncs := []database.QueryExecFunc{
		database.TxExecFunc(database.UserRole_AddToUser, userId, role.Slug, now),
	}

	if len(perms) > 0 {

		// this is slightly hacky
		valueStrings := make([]string, 0, len(perms))
		valueArgs := make([]interface{}, 0, len(perms)*5)
		for i := range perms {
			valueStrings = append(valueStrings, "(?, ?, ?, ?, ?)")
			valueArgs = append(valueArgs, userId)
			valueArgs = append(valueArgs, perms[i].Slug)
			valueArgs = append(valueArgs, false)
			valueArgs = append(valueArgs, now)
			valueArgs = append(valueArgs, time.Time{})
		}
		stmt := fmt.Sprintf("INSERT INTO users__permissions (user_id,permission_slug,added_on_user,created_at,deleted_at) VALUES %s", strings.Join(valueStrings, ","))
		txFuncs = append(txFuncs, database.TxExecFunc(stmt, valueArgs...))
	}

	return database.Transact(db, txFuncs)
}

// RemoveRoleFromUser removes one or more roles from a user/org. Wildcards not allowed for slug. If you want
// to remove multiple roles, call RolesForUser, and then loop over those to call this method.
func RemoveRoleFromUser(userId interface{}, roleSlug string) error {

	isValid, err := isValidSlug(roleSlug, false)
	if err != nil {
		return err
	}

	if !isValid {
		return fmt.Errorf("'%s' is not a valid roleSlug", roleSlug)
	}

	// look up all the userRoles the user currently has
	userRoles, err := RolesForUser(userId)
	if err != nil {
		return err
	}

	var userHasRole = false
	for _, v := range userRoles {
		if v.Slug == roleSlug {
			userHasRole = true
		}
	}

	// don't error out if the user doesn't have the roleToRemove
	if !userHasRole {
		return nil
	}

	// look up the target roleToRemove
	roleToRemove, err := RoleBySlug(roleSlug)
	if err != nil {
		return err
	} else if roleToRemove == nil {
		return fmt.Errorf("Failed to add roleToRemove '%s' to user. That roleToRemove does not exist.", roleSlug)
	}

	// before calculating unique permissions, remove target roleToRemove from list of user userRoles
	filteredRoles := make([]Role, len(userRoles)-1, len(userRoles)-1)
	for i, v := range userRoles {
		if v.Slug != roleToRemove.Slug {
			filteredRoles[i] = v
		}
	}

	// calculate the unique set of permissions we need to remove
	permissionsToRemove, err := uniquePermissionsForRole(*roleToRemove, filteredRoles)
	if err != nil {
		return err
	}

	err = doRolePermRemoval(roleToRemove, permissionsToRemove, userId)
	if err != nil {
		return err
	}

	return nil
}

// doRolePermRemoval removes a role and associated permissions from a user
func doRolePermRemoval(role *Role, perms []Permission, userId interface{}) error {

	// remove the role and permissions associated with the role
	txFuncs := []database.QueryExecFunc{
		database.TxExecFunc(database.UserRole_DeleteFromUser, userId, role.Slug),
	}

	if len(perms) > 0 {

		permSlugs := make([]string, len(perms), len(perms))
		for i, v := range perms {
			permSlugs[i] = v.Slug
		}

		args := map[string]interface{}{
			"userId": userId,
			"slugs":  permSlugs,
		}

		q, permQueryArgs, err := database.ProcessNamedQueryForIn(database.UserPermission_DeleteMany, args)
		if err != nil {
			return err
		}

		txFuncs = append(txFuncs, database.TxExecFunc(q, permQueryArgs...))
	}

	return database.Transact(db, txFuncs)
}

// RoleExists returns true if the slug corresponding to the supplied slug exists, or false if it does not
func RoleExists(slug string) (bool, error) {

	isValid, err := isValidSlug(slug, false)
	if err != nil {
		return false, err
	}

	if !isValid {
		return false, fmt.Errorf("'%s' is not a valid slug", slug)
	}

	_, err = RoleBySlug(slug)
	if err == ErrNoSuchRole {
		return false, nil
	} else if err != nil {
		return false, err
	}

	return true, nil
}

// RoleBySlug fetches a role by its slug. Wildcard not allowed.
func RoleBySlug(slug string) (*Role, error) {

	isValid, err := isValidSlug(slug, true)
	if err != nil {
		return nil, err
	}

	if !isValid {
		return nil, fmt.Errorf("'%s' is not a valid slug", slug)
	}

	var r Role
	err = db.Get(&r, database.Role_SelectBySlug, slug, time.Time{})

	if err == sql.ErrNoRows {
		return nil, ErrNoSuchRole
	} else if err != nil {
		return nil, fmt.Errorf("Error fetching role: %s", slug)
	}

	return &r, nil
}

// RolesWithPermission returns the Roles that have a given permission. Wildcard allowed.
func RolesWithPermission(slug string) ([]Role, error) {

	isValid, err := isValidSlug(slug, false)
	if err != nil {
		return nil, err
	}

	if !isValid {
		return nil, fmt.Errorf("'%s' is not a valid slug", slug)
	}

	isWildcard, err := isWildcardSlug(slug)
	if err != nil {
		return nil, err
	}

	q := database.RolePermission_SelectWithPermission
	if isWildcard {
		slug = strings.Replace(slug, `*`, `%`, -1)
		q = database.RolePermission_SelectWithPermissionWildcard
	}

	var roles []Role
	err = db.Select(&roles, q, slug, time.Time{})
	if err != nil {
		return nil, err
	}

	return roles, nil
}

// UsersForRole retrieves the users that have the given role
func CountUsersForRole(slug string) (int, error) {

	var args = []interface{}{
		slug,
		time.Time{},
	}

	var count int
	err := db.Get(&count, database.UserRole_CountUsersForRole, args...)
	if err != nil {
		if err == sql.ErrNoRows {
			return 0, nil
		} else {
			return 0, err
		}
	}

	return count, nil
}

// UsersForRole retrieves the users that have the given role
func UsersForRole(slug string) ([]User, error) {

	var args = []interface{}{
		slug,
		time.Time{},
	}

	var users = []User{}
	err := db.Select(&users, database.UserRole_SelectUsersForRole, args...)
	if err != nil {
		if err == sql.ErrNoRows {
			return users, nil
		} else {
			return nil, err
		}
	}

	return users, nil
}

// UserHasRole returns true if a user has the given role and false if it does not. Wildcards allowed.
func UserHasRole(userId interface{}, slug string) (bool, error) {

	isValid, err := isValidSlug(slug, true)
	if err != nil {
		return false, err
	}

	if !isValid {
		return false, fmt.Errorf("'%s' is not a valid slug", slug)
	}

	isWildcard, err := isWildcardSlug(slug)
	if err != nil {
		return false, fmt.Errorf("'%s' is not a valid wildcard slug")
	}

	var (
		q    string
		args = []interface{}{
			userId,
		}
	)

	if isWildcard {
		q = database.Role_CountWildcardForUser
		args = append(args, trimWildcard(slug)+`%`)
	} else {
		q = database.Role_CountForUser
		args = append(args, slug)
	}
	args = append(args, time.Time{})

	var count int
	err = db.Get(&count, q, args...)

	if count == 0 || err == sql.ErrNoRows {
		return false, nil
	} else if err != nil {
		return false, fmt.Errorf("Error fetching role: %s", slug)
	}

	return count > 0, nil
}

// RolesForUser retrieves the roles assigned the the given user id
func RolesForUser(userId interface{}) ([]Role, error) {

	var (
		q    string
		args []interface{}
	)

	q = database.Role_SelectAllForUser
	args = []interface{}{
		userId,
		time.Time{},
	}

	var roles = make([]Role, 0)
	err := db.Select(&roles, q, args...)
	if err != nil {
		if err == sql.ErrNoRows {
			return roles, nil
		} else {
			return nil, err
		}
	}

	return roles, nil
}

// add a permission to this role. Permission can be either a new permission or an
// existing one. If an existing permission is given, the name and description parameters
// are ignored.
func (r *Role) AddPermission(slug, name, description string) error {

	isValid, err := isValidSlug(slug, false)
	if err != nil {
		return err
	}

	if !isValid {
		return fmt.Errorf("'%s' is not a valid slug", slug)
	}

	permissionExists, err := PermissionExists(slug)
	if err != nil {
		return err
	}

	if !permissionExists {

		_, err = AddNewPermission(slug, name, description)
		if err != nil {
			return err
		}
	}

	roleHasPermission, err := r.HasPermission(slug)
	if err != nil {
		return err
	}

	if roleHasPermission {
		return nil
	}

	err = database.Exec1Row(db, database.RolesPermissions_AddPermissionToRole, r.Slug, slug, time.Now(), time.Time{})
	if err != nil {
		return err
	}

	return nil
}

// Permissions retrieves the permissions for this role
func (r *Role) Permissions() ([]Permission, error) {

	var perms = make([]Permission, 0)
	err := db.Select(&perms, database.Role_SelectPermissions, r.Slug, time.Time{})
	if err != nil {
		if err == sql.ErrNoRows {
			return perms, nil
		} else {
			return nil, err
		}
	}

	return perms, nil
}

// PermissionSlugs returns a slice of the permission slugs matching this role
func (r *Role) PermissionSlugs() ([]string, error) {

	var permSlugs = make([]string, 0)
	err := db.Select(&permSlugs, database.Role_SelectPermissionSlugs, r.Slug, time.Time{})
	if err != nil && err != sql.ErrNoRows {
		return nil, err
	}

	return permSlugs, nil
}

// HasPermission returns true if the role contains the permission, false if it does not. Wildcards allowed.
func (r *Role) HasPermission(slug string) (bool, error) {

	isValid, err := isValidSlug(slug, true)
	if err != nil {
		return false, err
	}

	if !isValid {
		return false, fmt.Errorf("'%s' is not a valid slug", slug)
	}

	isWildcard, err := isWildcardSlug(slug)
	if err != nil {
		return false, nil
	}

	var (
		query string
		arg   = slug
		count = 0
	)

	if isWildcard {
		query = database.Permission_WildcardCountForRole
		arg = trimWildcard(slug) + `%`
	} else {
		query = database.Permission_CountForRole
	}

	args := []interface{}{
		arg,
		time.Time{},
	}

	err = db.Get(&count, query, args...)
	if err != nil {
		return false, err
	}

	return count > 0, nil
}

// Permission model
type Permission struct {
	Slug        string    `db:"permission_slug"`
	Name        string    `db:"permission_name"`
	Description string    `db:"permission_description"`
	CreatedAt   time.Time `db:"created_at"`
	DeletedAt   time.Time `db:"deleted_at"`
}

// User-Permission join table model
type UserPermission struct {
	UserId         string    `db:"user_id"`
	PermissionSlug string    `db:"permission_slug"`
	AddedOnUser    bool      `db:"added_on_user"`
	CreatedAt      time.Time `db:"created_at"`
	DeletedAt      time.Time `db:"deleted_at"`
}

// AllPermissions returns all the permissions in the db
func AllPermissions() ([]Permission, error) {

	var permissions []Permission
	err := db.Select(&permissions, database.Permission_SelectAll, time.Time{})
	if err != nil {
		return nil, err
	}

	return permissions, nil
}

// RemovePermission remove the specified permission. It must not be owned by any role when this function is
// called. Wildcard not allowed.
func DeletePermission(slug string) error {

	isWildCard, err := isWildcardSlug(slug)
	if err != nil {
		return err
	}

	if isWildCard {
		return errors.New("wildcard slugs now allowed for RemovePermission")
	}

	r, err := RolesWithPermission(slug)
	if err != nil && err != sql.ErrNoRows {
		return err
	}

	if len(r) > 0 {
		return fmt.Errorf("There are %i roles that contain the permission '%s'. Remove the permission from those roles before removing this permission.", len(r), slug)
	}

	err = database.Exec1Row(db, database.Permission_Delete, time.Now(), slug)
	if err != nil && err != sql.ErrNoRows {
		return err
	}

	return nil
}

// PermissionExists returns true if the permission matching the supplied slug exists. Wildcards not allowed.
func PermissionExists(slug string) (bool, error) {

	isValid, err := isValidSlug(slug, false)
	if err != nil {
		return false, err
	}

	if !isValid {
		return false, fmt.Errorf("'%s' is not a valid slug", slug)
	}

	_, err = PermissionBySlug(slug)
	if err == ErrNoSuchPermission {
		return false, nil
	} else if err != nil {
		return false, err
	}

	return true, nil
}

// PermissionBySlug gets a permission by its slug. Wildcards not allowed.
func PermissionBySlug(slug string) (*Permission, error) {

	isValid, err := isValidSlug(slug, false)
	if err != nil {
		return nil, err
	}

	if !isValid {
		return nil, fmt.Errorf("'%s' is not a valid slug", slug)
	}

	var p Permission
	err = db.Get(&p, database.Permission_SelectBySlug, slug, time.Time{})

	if err == sql.ErrNoRows {
		return nil, ErrNoSuchPermission
	} else if err != nil {
		return nil, fmt.Errorf("Error fetching permission: %s", slug)
	}

	return &p, nil
}

// AddPermissionToUser adds permissions to a user. You can only add permissions that are not otherwise associated with
// one of the user's roles. If you need to add a permission that is also on one of the user's roles,
// first remove that role, then individually add back any permission(s) needed
func AddPermissionToUser(userId, slug string) error {

	isValid, err := isValidSlug(slug, false)
	if err != nil {
		return err
	}

	if !isValid {
		return fmt.Errorf("'%s' is not a valid slug", slug)
	}

	// Validate that the permissions already exist in the system. Can't add new permissions this way
	// This isn't a heavily used function, but it could obviously be optimized for bulk lookups
	exists, err := PermissionExists(slug)
	if err != nil {
		if err == sql.ErrNoRows {
			return fmt.Errorf("The permission slug '%s' doesn't exist.", slug)
		} else {
			return fmt.Errorf("Failed to look up permission slug '%s'.", slug)
		}
	}

	if !exists {
		return fmt.Errorf("The permission slug '%s' doesn't exist.", slug)
	}

	var existingPerms []UserPermission
	err = db.Select(&existingPerms, database.UserPermission_SelectForUser, userId, time.Time{})
	if err != nil && err != sql.ErrNoRows {
		return err
	}

	for _, v := range existingPerms {
		if v.PermissionSlug == slug {
			if v.AddedOnUser {
				return nil // no-op if already added correctly
			}

			return fmt.Errorf("User already has permission added via a role '%s'.", slug)
		}
	}

	// user_id,permission_slug,added_on_user,created_at,deleted_at
	err = database.Exec1Row(db, database.UserPermission_Insert, userId, slug, true, time.Now(), time.Time{})
	if err != nil {
		return err
	}

	return nil
}

// PermissionsForUser returns the permissions for the user with the given id
func PermissionsForUser(userId interface{}, set PermissionSetType) ([]Permission, error) {

	q := database.Permission_SelectForUser
	switch set {
	case RolePermissionsSet:
		q += ` AND added_on_user=false`
	case UserPermissionsSet:
		q += ` AND added_on_user=true`
	}

	var existingPerms []Permission
	err := db.Select(&existingPerms, q, userId, time.Time{})
	if err != nil && err != sql.ErrNoRows {
		return existingPerms, err
	}

	return existingPerms, nil
}

// UsersWithPermission returns the users for the permission with the given slug. Wildcard is allowed.
func UsersWithPermission(slug string) ([]User, error) {

	var users []User

	isValid, err := isValidSlug(slug, false)
	if err != nil {
		return nil, err
	}

	if !isValid {
		return nil, fmt.Errorf("'%s' is not a valid slug", slug)
	}

	isWildcard, err := isWildcardSlug(slug)
	if err != nil {
		return nil, err
	}

	q := database.UserPermission_SelectUsersForPermission
	if isWildcard {
		q = database.UserPermission_SelectUsersForPermissionWildcard
	}

	err = db.Select(&users, q, slug, time.Time{})
	if err != nil && err != sql.ErrNoRows {
		return users, err
	}

	return users, nil
}

// RemovePermissionFromUser removes a permission from a user. Only permissions that are not otherwise associated
// with one of the user's roles can be removed. Wildcards not allowed. No error is returned if the user does not
// have the permission
func RemovePermissionFromUser(userId, slug string) error {

	isValid, err := isValidSlug(slug, false)
	if err != nil {
		return err
	}

	if !isValid {
		return fmt.Errorf("'%s' is not a valid slug", slug)
	}

	var up UserPermission
	err = db.Get(&up, database.UserPermission_SelectBySlug, userId, slug, time.Time{})
	if err != nil {
		return err
	}

	if &up == nil {
		return nil
	}

	if !up.AddedOnUser {
		return fmt.Errorf("Permission '%s' cannot be removed because it was added via a role", slug)
	}

	err = database.Exec1Row(db, database.UserPermission_Delete, time.Now(), userId, slug)
	if err != nil {
		return err
	}

	return nil
}

// AddNewPermission adds a permission to the db. This is different from
// Role.AddNewPermission which adds a permission to a role, whereas this only adds an unassociated
// permission
func AddNewPermission(slug, name, description string) (*Permission, error) {

	isValid, err := isValidName(name)
	if err != nil {
		return nil, err
	}

	if !isValid {
		return nil, fmt.Errorf("'%s' is not a valid name", slug)
	}

	isValid, err = isValidSlug(slug, false)
	if err != nil {
		return nil, err
	}

	if !isValid {
		return nil, fmt.Errorf("'%s' is not a valid slug", slug)
	}

	isValid, err = isValidDescription(description)
	if err != nil {
		return nil, err
	}

	if !isValid {
		return nil, fmt.Errorf("'%s' is not a valid description", slug)
	}

	roleExists, err := PermissionExists(slug)
	if err != nil {
		return nil, err
	}

	if roleExists {
		return nil, fmt.Errorf("Cannot insert permission. Permission with slug '%s' already exists", slug)
	}

	p := Permission{
		Slug:        slug,
		Name:        name,
		Description: description,
		CreatedAt:   time.Now(),
		DeletedAt:   time.Time{},
	}

	err = database.Exec1Row(db, database.Permission_Insert, p.Slug, p.Name, p.Description, p.CreatedAt, p.DeletedAt)
	if err != nil {
		return nil, err
	}

	return &p, nil
}

// Matches returns true if the supplied slug matches the slug for this permission. accepts wildcards
func (p *Permission) Matches(slug string) (bool, error) {

	isValidSlug, err := isValidSlug(slug, true)
	if err != nil {
		return false, err
	}

	if !isValidSlug {
		return false, errors.New("bad slug")
	}

	isWildcard, _ := isWildcardSlug(slug)
	if isWildcard {
		slug := trimWildcard(slug)
		return strings.HasPrefix(p.Slug, slug), nil
	} else {
		return p.Slug == slug, nil
	}
}

// Roles returns the Role objects that contain this permission
func (p *Permission) Roles() ([]Role, error) {

	isWildcard, err := isWildcardSlug(p.Slug)
	if err != nil {
		return nil, err
	}

	if isWildcard {
		return nil, fmt.Errorf("Can't fetch roles for wildcard slug: '%s'", p.Slug)
	}

	var roles = []Role{}
	err = db.Select(&roles, database.Permission_SelectRoles, p.Slug, time.Time{})
	if err != nil {
		return nil, err
	}

	return roles, nil
}

// uniquePermissionsForRoles takes a slice of roles and returns the set of unique permissions represented by them
func uniquePermissionsForRoles(roles []Role) ([]Permission, error) {

	var permSlice = []Permission{}

	// nil and empty need different handling
	if roles == nil {
		return permSlice, errors.New("received nil arg for roles")
	}

	rolesLen := len(roles)

	if rolesLen == 0 {
		return permSlice, nil
	}

	var roleSlugs = make([]string, rolesLen, rolesLen)
	for i, v := range roles {
		roleSlugs[i] = v.Slug
	}

	arg := map[string]interface{}{
		"roles":     roleSlugs,
		"deletedat": time.Time{},
	}

	q, args, err := database.ProcessNamedQueryForIn(database.Permission_AllForRoles, arg)
	if err != nil {
		fmt.Printf("Err1: %s\n", err.Error())
		return nil, err
	}

	err = db.Select(&permSlice, q, args...)
	if err != nil {
		fmt.Printf("Err2: %s\n", err.Error())
		return nil, err
	}

	// hacky way to filter non-uniques
	permMap := make(map[string]Permission, 0)
	for _, v := range permSlice {
		permMap[v.Slug] = v
	}

	i := 0
	permSlice = make([]Permission, len(permMap), len(permMap))
	for _, v := range permMap {
		permSlice[i] = v
		i++
	}

	return permSlice, nil
}

// uniquePermissionsForRole takes a role and a slice of roles to compare against, returns all the permissions in first role that are not
// contained in the slice of roles.
func uniquePermissionsForRole(role Role, roles []Role) ([]Permission, error) {

	comparativePermSet, err := uniquePermissionsForRoles([]Role{
		role,
	})

	if err != nil {
		return nil, err
	}

	comparatorPermSet, err := uniquePermissionsForRoles(roles)
	if err != nil {
		return nil, err
	}

	var uniquePerms = []Permission{}

	// iterate over comparative first f/c comparator set can be empty
COMPARATIVE:
	for _, v := range comparativePermSet {
		for _, x := range comparatorPermSet {
			if v.Slug == x.Slug {
				continue COMPARATIVE
			}
		}
		uniquePerms = append(uniquePerms, v)
	}

	return uniquePerms, nil
}

// UserHasPermission tests whether a user has a particular permission. Accepts wildcards.
func UserHasPermission(userId interface{}, slug string) (bool, error) {

	var (
		q        string
		queryArg = slug
	)

	// get the unique permissions for the user, then do wildcard match. Since both wildcard and normal
	// are allowed, have to validate for both.
	valid, err := isValidSlug(slug, true)
	if err != nil {
		return false, err
	}

	if !valid {
		return false, fmt.Errorf("slug '%s' is not valid", slug)
	}

	isWildcard, err := isWildcardSlug(slug)
	if err != nil {
		return false, err
	}

	if isWildcard {
		q = database.Permission_WildcardCountForUser
		queryArg = trimWildcard(slug) + `%`
	} else {
		q = database.Permission_CountForUser
	}

	var count int
	err = db.Get(&count, q, []interface{}{
		queryArg,
		time.Time{},
	})

	if err == sql.ErrNoRows {
		return false, nil
	} else if err != nil {
		return false, fmt.Errorf("Error fetching role: %s", slug)
	}

	return true, nil
}

// isValidName returns true if the supplied description is valid. Alpha plus space is permitted
func isValidName(name string) (bool, error) {

	if len(name) > MaxNameLen {
		return false, errors.New("name is too long")
	}

	// abc, abc.*, abc.xyz or abc.xyz.*  Wildcard must be preceded by dot.
	if !regexp.MustCompile(`^[a-zA-Z ]+$`).MatchString(name) {
		return false, errors.New("name failed regex")
	}

	return true, nil
}

// isValidSlug returns true if the slug is valid, or false if it is not. Valid slugs are
// all lower-case, all alphabetic except where they are delineated by dots. Wildcard slugs
// append as asterisk to the end, but only after a dot boundary. Valid examples :
// abc, abc.*, abc.xyz or abc.xyz.*
func isValidSlug(slug string, allowWildcard bool) (bool, error) {

	if len(slug) > MaxSlugLen {
		return false, errors.New("slug is too long")
	}

	// abc, abc.*, abc.xyz or abc.xyz.*  Wildcard must be preceded by dot.
	if !regexp.MustCompile(`^(?:(?:[a-z]+)(?:\.[a-z]+|\.\*)*)+$`).MatchString(slug) {
		return false, errors.New("slug failed regex")
	}

	if !allowWildcard && strings.Contains(slug, `*`) {
		return false, errors.New("wildcard not allowed")
	}

	return true, nil
}

// isValidDescription returns true if the supplied description is valid. Alphanumeric plus space, apostrophe,
// period (stop) and comma are permitted
func isValidDescription(desc string) (bool, error) {

	if len(desc) > MaxDescriptionLen {
		return false, errors.New("description is too long")
	}

	if !regexp.MustCompile(`^[a-zA-Z0-9 ,'.]+$`).MatchString(desc) {
		return false, errors.New("description failed regex (alphanum plus space, apostrophe and comma)")
	}

	return true, nil
}

// isWildcardSlug returns true if the supplied slug is a valid wildcard slug, or false otherwise
func isWildcardSlug(slug string) (bool, error) {
	_, err := isValidSlug(slug, true)
	if err != nil {
		return false, err
	}

	return strings.HasSuffix(slug, `*`), nil
}

// trimWildcard trims wildcard characters from a slug. Assumes slug is valid according to isValidSlug
func trimWildcard(slug string) string {
	return slug[0 : len(slug)-2]
}
