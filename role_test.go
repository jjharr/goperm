package goperm

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

var testUserId string

func TestSetupRoleTest(t *testing.T) {

	// todo - create a dummy test user id
	testUserId = "xyz"
}

func TestInsertRole(t *testing.T) {
	_, err := AddNewRole(`test`, `Test`, `This is a test role`)
	assert.Nil(t, err, "Failed to insert simple role")

	// used later for additional tests
	_, err = AddNewRole(`testtwo`, `Test Two`, `This is another test role`)
	assert.Nil(t, err, "Failed to insert simple role")

	_, err = AddNewRole(`test.hierarchical`, `Hierarchical Test`, `This is a herarchical test role`)
	assert.Nil(t, err, "Failed to insert hierarchical role")

	_, err = AddNewRole(`test*`, `First Invalid Test`, `The first invalid test`)
	assert.NotNil(t, err, "Failed to insert hierarchical role")

	_, err = AddNewRole(`test`, `Pre-existing test`, `Try to insert a role that already exists`)
	assert.NotNil(t, err, "Failed to insert hierarchical role")
}

func TestRoleBySlug(t *testing.T) {
	role, err := RoleBySlug(`test`)
	assert.Nil(t, err)
	assert.Equal(t, role.Slug, `test`)
	assert.Equal(t, role.Name, `Test`)
	assert.Equal(t, role.Description, `This is a test role`)

	role, err = RoleBySlug(`htrwhtrw`)
	assert.NotNil(t, err)
	assert.Nil(t, role)
}

func TestRoleExists(t *testing.T) {
	exists, err := RoleExists(`test`)
	assert.Nil(t, err)
	assert.Equal(t, exists, true)

	exists, err = RoleExists(`test.*`)
	assert.NotNil(t, err)
	assert.False(t, exists)

	exists, err = RoleExists(`htrwhtrw`)
	assert.Nil(t, err)
	assert.False(t, exists)
}

func TestAllRoles(t *testing.T) {
	roles, err := AllRoles()
	assert.Nil(t, err)
	assert.Len(t, roles, 5, `Incorrect number of roles`)
}

func TestDeleteRole(t *testing.T) {
	_, err := AddNewRole(`deleteme`, `Delete ME`, `This is a deleteable test role`)
	assert.Nil(t, err, "Failed to insert deleteable role")

	err = DeleteRole(`deleteme`)
	assert.Nil(t, err, "Failed to delete role")

	exists, err := RoleExists(`deleteme`)
	assert.Nil(t, err)
	assert.False(t, exists)
}

func TestAddPermission(t *testing.T) {
	// additional permissions used for later tests
	_, err := AddNewPermission(`test.permission`, `Test Permission`, `A test permission`)
	assert.Nil(t, err)

	_, err = AddNewPermission(`test.permission.first`, `First Test Permission`, `The first test permission`)
	assert.Nil(t, err)

	_, err = AddNewPermission(`test.permission.second`, `Second Test Permission`, `The second test permission`)
	assert.Nil(t, err)
}

func TestPermissionExists(t *testing.T) {
	exists, err := PermissionExists(`test.permission.first`)
	assert.Nil(t, err)
	assert.True(t, exists)

	exists, err = PermissionExists(`test.permission.*`)
	assert.NotNil(t, err)
	assert.False(t, exists)

	exists, err = PermissionExists(`test.nopermission`)
	assert.Nil(t, err)
	assert.False(t, exists)
}

func TestPermissionBySlug(t *testing.T) {
	p, err := PermissionBySlug(`test.permission.first`)
	assert.Nil(t, err)
	assert.IsType(t, &Permission{}, p)
	assert.NotZero(t, p)

	p, err = PermissionBySlug(`test.permission.*`)
	assert.NotNil(t, err)
	assert.Nil(t, p)

	p, err = PermissionBySlug(`test.nopermission`)
	assert.NotNil(t, err)
	assert.Nil(t, p)
}

func TestPermissionMatches(t *testing.T) {
	p, err := PermissionBySlug(`test.permission.first`)
	assert.Nil(t, err)
	assert.IsType(t, &Permission{}, p)
	assert.NotZero(t, p)

	matches, err := p.Matches(`test.permission.first`)
	assert.Nil(t, err)
	assert.True(t, matches)

	matches, err = p.Matches(`test.permission.*`)
	assert.Nil(t, err)
	assert.True(t, matches)

	matches, err = p.Matches(`test.no`)
	assert.Nil(t, err)
	assert.False(t, matches)
}

func TestAddPermissionToRole(t *testing.T) {
	r, err := RoleBySlug(`test`)
	assert.Nil(t, err)
	err = r.AddPermission(`test.permission.first`, ``, ``)
	assert.Nil(t, err)

	// add a new permission
	r, err = RoleBySlug(`test`)
	assert.Nil(t, err)
	err = r.AddPermission(`test.permission.third`, `Third Test Permission`, `The third test permission`)
	assert.Nil(t, err)

	// these are added for later user tests
	r, err = RoleBySlug(`testtwo`)
	assert.Nil(t, err)
	err = r.AddPermission(`test.permission.first`, ``, ``)
	assert.Nil(t, err)
	err = r.AddPermission(`test.permission.second`, ``, ``)
	assert.Nil(t, err)
}

func TestPermissionRoles(t *testing.T) {
	p, err := PermissionBySlug(`test.permission.first`)
	assert.Nil(t, err)
	assert.IsType(t, &Permission{}, p)
	assert.NotZero(t, p)

	roles, err := p.Roles()
	assert.Nil(t, err)
	assert.IsType(t, []Role{}, roles)
	assert.Len(t, roles, 1)
}

func TestRoleHasPermission(t *testing.T) {
	r, err := RoleBySlug(`test`)
	assert.Nil(t, err)
	exists, err := r.HasPermission(`test.permission.second`)
	assert.Nil(t, err)
	assert.True(t, exists)

	exists, err = r.HasPermission(`test.permission.*`)
	assert.Nil(t, err)
	assert.True(t, exists)

	exists, err = r.HasPermission(`test.nopermission`)
	assert.Nil(t, err)
	assert.False(t, exists)

	exists, err = r.HasPermission(`test.nopermission.*`)
	assert.Nil(t, err)
	assert.False(t, exists)
}

func TestRolePermissions(t *testing.T) {
	r, err := RoleBySlug(`test`)
	assert.Nil(t, err)
	p, err := r.Permissions()
	assert.Nil(t, err)
	assert.IsType(t, []Permission{}, p)
	assert.Equal(t, len(p), 2)
}

func TestRolePermissionSlugs(t *testing.T) {
	r, err := RoleBySlug(`test`)
	assert.Nil(t, err)
	p, err := r.PermissionSlugs()
	assert.Nil(t, err)
	assert.IsType(t, []string{}, p)
	assert.Equal(t, len(p), 2)
}

func TestAddRoleToUser(t *testing.T) {

	err := AddRoleToUser(testUserId, `test`)
	assert.Nil(t, err)

	err = AddRoleToUser(testUserId, `testtwo`)
	assert.Nil(t, err)
}

func TestUserHasRole(t *testing.T) {

	hasRole, err := UserHasRole(testUserId, `test`)
	assert.Nil(t, err)
	assert.True(t, hasRole)

	hasRole, err = UserHasRole(testUserId, `test.*`)
	assert.Nil(t, err)
	assert.True(t, hasRole)

	hasRole, err = UserHasRole(testUserId, `test.hierarchical`)
	assert.Nil(t, err)
	assert.False(t, hasRole)
}

func TestUserHasPermission(t *testing.T) {

	hasPermission, err := UserHasPermission(testUserId, `test.permission.first`)
	assert.Nil(t, err)
	assert.True(t, hasPermission)

	hasPermission, err = UserHasPermission(testUserId, `test.*`)
	assert.Nil(t, err)
	assert.True(t, hasPermission)

	hasPermission, err = UserHasPermission(testUserId, `noperm`)
	assert.Nil(t, err)
	assert.False(t, hasPermission)
}

func TestAddPermissionToUser(t *testing.T) {

	_, err := AddNewPermission(`custom.permission`, `Custom`, `A Custom Test Permission`)
	assert.Nil(t, err)

	err = AddPermissionToUser(testUserId, `custom.permission`)
	assert.Nil(t, err)

	hasPermission, err := UserHasPermission(testUserId, `custom.permission`)
	assert.Nil(t, err)
	assert.True(t, hasPermission)

	// should fail to add permission that was already added via a role
	err = AddPermissionToUser(testUserId, `test.permission.first`)
	assert.NotNil(t, err)
}

func TestRemovePermissionToUser(t *testing.T) {

	err := RemovePermissionFromUser(testUserId, `custom.permission`)
	assert.Nil(t, err)

	hasPermission, err := UserHasPermission(testUserId, `custom.permission`)
	assert.Nil(t, err)
	assert.False(t, hasPermission)

	err = RemovePermissionFromUser(testUserId, `test.permission.first`)
	assert.NotNil(t, err)
}

func TestRolesForUser(t *testing.T) {

	roles, err := RolesForUser(testUserId)
	assert.Nil(t, err)
	assert.IsType(t, []Role{}, roles)
	assert.Len(t, roles, 2)
}

func TestRemoveRoleFromUser(t *testing.T) {

	err := RemoveRoleFromUser(testUserId, `testtwo`)
	assert.Nil(t, err)

	hasRole, err := UserHasRole(testUserId, `testtwo`)
	assert.Nil(t, err)
	assert.False(t, hasRole)

}

func TestBreakdownRoleTest(t *testing.T) {
}
