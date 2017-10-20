package database

const (

	Role_SelectAll = `SELECT * FROM roles WHERE deleted_at=$1`

	Permission_SelectAll = `SELECT * FROM permissions WHERE deleted_at=$1`

	Permission_Insert = `INSERT INTO permissions (permission_slug,permission_name,permission_description,created_at,deleted_at)
	VALUES ($1,$2,$3,$4,$5)`

	Permission_SelectBySlug = `SELECT * FROM permissions
		WHERE permission_slug=$1 AND deleted_at=$2 LIMIT 1`

	Permission_CountForUser = `SELECT count(*) FROM permissions
		WHERE permission_slug=$1 AND deleted_at=$2`

	Permission_WildcardCountForUser = `SELECT count(*) FROM permissions
		WHERE permission_slug LIKE $1 AND deleted_at=$2`

	Permission_SelectRoles = `SELECT roles.* FROM roles
		JOIN roles__permissions ON roles__permissions.role_slug=roles.role_slug
		WHERE roles__permissions.permission_slug=$1 AND roles__permissions.deleted_at=$2`

	Permission_AllForRoles = `SELECT permissions.* FROM roles__permissions
		JOIN permissions ON permissions.permission_slug=roles__permissions.permission_slug
		WHERE roles__permissions.role_slug IN(:roles) AND roles__permissions.deleted_at=:deletedat`

	Permission_CountForRole = `SELECT count(*) from roles__permissions
		WHERE permission_slug=$1 AND deleted_at=$2`

	Permission_WildcardCountForRole = `SELECT count(*) from roles__permissions
		WHERE permission_slug LIKE $1 AND deleted_at=$2`

	UserPermission_SelectBySlug = `SELECT * FROM users__permissions
		WHERE user_id=$1 AND permission_slug=$2 AND deleted_at=$3`

	UserPermission_SelectForUser = `SELECT * FROM users__permissions
		WHERE user_id=$1 AND deleted_at=$2`

	UserPermission_SelectUsersForPermission = `SELECT users.* FROM users__permissions
		JOIN users ON users__permissions.user_id = users.id
		WHERE users__permissions.permission_slug=$1 AND users__permissions.deleted_at=$2`

	UserPermission_SelectUsersForPermissionWildcard = `SELECT users.* FROM users__permissions
		JOIN users ON users__permissions.user_id = users.id
		WHERE users__permissions.permission_slug LIKE $1 AND users__permissions.deleted_at=$2`

	Permission_SelectForUser = `SELECT permissions.* FROM users__permissions
		JOIN permissions ON users__permissions.permissions_slug = permissions.slug
		WHERE users__permissions.user_id=$1 AND users__permissions.deleted_at=$2`

	UserPermission_Delete = `UPDATE users__permissions SET deleted_at=$1 WHERE user_id=$2 and permission_slug=$2`

	UserPermission_DeleteMany = `DELETE FROM users__permissions WHERE user_id=$1 AND permission_slug IN(:slugs)`

	UserPermission_Insert = `INSERT INTO users__permissions (user_id,permission_slug,added_on_user,created_at,deleted_at)
		VALUES ($1,$2,$3,$4,$5)`

	Role_SelectBySlug = `SELECT * FROM roles
		WHERE role_slug=$1 AND deleted_at=$2`

	UserRole_AddToUser = `INSERT INTO users__roles (user_id,role_slug,created_at)
		VALUES ($1,$2,$3)`

	UserRole_DeleteFromUser = `DELETE FROM users__roles WHERE user_id=$1 AND role_slug=$2`

	Role_Insert = `INSERT INTO roles (role_slug,role_name,role_description,created_at,deleted_at)
	VALUES ($1,$2,$3,$4,$5)`

	RolePermission_SelectWithPermission = `SELECT roles.* FROM roles__permissions
		JOIN roles ON roles__permissions.role_slug = roles.slug
		WHERE roles__permissions.role_slug=$1 and roles__permissions.deleted_at=$2`

	RolePermission_SelectWithPermissionWildcard = `SELECT roles.* FROM roles__permissions
		JOIN roles ON roles__permissions.role_slug = roles.slug
		WHERE roles__permissions.role_slug LIKE $1 and roles__permissions.deleted_at=$2`

	RolePermission_Delete = `UPDATE roles SET deleted_at=$1
		WHERE role_slug=$2 AND deleted_at=$3`

	Role_Delete = `UPDATE roles SET deleted_at=$1
		WHERE role_slug=$2`

	Permission_Delete = `UPDATE permissions SET deleted_at=$1
		WHERE permissions_slug=$2`

	Role_SelectAllForUser = `SELECT roles.* FROM users__roles
	 	JOIN roles ON roles.role_slug=users__roles.role_slug
	 	WHERE users__roles.user_id=$1 AND users__roles.deleted_at=$2`

	UserRole_CountUsersForRole = `SELECT count(*) FROM users__roles WHERE role_slug=$1 AND deleted_at=$3`

	UserRole_SelectUsersForRole = `SELECT users.* FROM users__roles
		JOIN users ON users__roles.user_id = users.id
		WHERE users__roles.role_slug=$1 AND users__roles.deleted_at=$2`

	Role_CountForUser = `SELECT count(*) FROM users__roles WHERE user_id=$1 AND role_slug=$2 AND deleted_at=$3`

	Role_CountWildcardForUser = `SELECT count(*) FROM users__roles
		WHERE user_id=$1 AND role_slug LIKE $2 AND deleted_at=$3`

	Role_SelectPermissions = `SELECT permissions.* FROM roles__permissions
		JOIN permissions ON roles__permissions.permission_slug=permissions.permission_slug
		WHERE roles__permissions.role_slug=$1 AND roles__permissions.deleted_at=$2`

	Role_SelectPermissionSlugs = `SELECT permission_slug FROM roles__permissions
		WHERE roles__permissions.role_slug=$1 AND deleted_at=$2`

	RolesPermissions_AddPermissionToRole = `INSERT INTO roles__permissions (role_slug,permission_slug,created_at,deleted_at)
		VALUES ($1,$2,$3,$4)`
)