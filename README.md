# Goperm - Go roles and permissions

Goperm provides full-featured roles and permissions. It's very powerful, but the code has been extracted from a live application and
currently requires some adaptation to your own application. Still working to generalize the package and remove
the remaining external dependencies.

## Features

### Easy to use
Most functions just take simple strings as arguments. No cumbersome building of objects just to do a simple lookup. These strings can be implemented as constants to get better autocompletion support to make them even easier.

    UserHasRole("staff.sales")

### Hierarchical roles and permissions with wildcard support
Avoid complicated checks by using hierarchical roles or permissions with wildcards :

    AddRoleToUser(userId, "staff.sales.support")
    UserHasRole(userId, "staff.sales.*") // true
    
### Give users roles made of permissions

    r := AddRole("staff.sales", "Sales Staff", "The Sales Staff")
    err := r.AddPermission("can_view_own_leads", "View Leads", "")
    err = r.AddPermission("can_edit_own_leads", "Edit Leads", "")
    AddRoleToUser(userId, "staff.sales")
    UserHasPermission(userId, "can_view_own_leads") // true

### Give users permissions directly

    err := AddPermissionToUser(userId, "can_view_own_leads")
    UserHasPermission(userId, "can_view_own_leads") // true

### Or do both

    r := AddRole("staff.sales", "Sales Staff", "The Sales Staff")
    err := r.AddPermission("can_view_own_leads", "View Leads", "")
    err = r.AddPermission("can_edit_own_leads", "Edit Leads", "")
    err = AddRoleToUser(userId, "staff.sales")
    err = AddPermissionToUser(userId, "can_view_european_leads")
    
    UserHasPermission(user_id, "can_view_own_leads") // true
    UserHasPermission(user_id, "can_view_european_leads") // true


### Plenty of support for role and permission admin
Want to create a dashboard for checking and admin of roles and permissions?

    Add/DeleteRole()
    Add/DeletePermission()
    AllRoles()
    AllPermissions()
    UsersWithRole(slug string)
    RolesForUser(userId interface{})
    r.Permissions() // list permissions for given role
    UsersWithPermission(slug string)
    PermissionsForUser(userId interface{})
    RolesWithPermission(slug string)

There are also functions for removing roles and permissions from users.

### Does the "right" thing
Goperm tries to be smart about doing the right thing :

 1. If you add roles with overlapping permissions, it will let you. If you later remove one of those roles, it will only remove the unique permissions for that role.
 2. It keeps track of how a permission was added to a user (via a role or directly), so you can configure it to add a permission to a user even if that permission already exists in a role the user has. If you remove the role, the independently-added permission remains. (By default
this is turned off, because this can be a confusing feature).
 3. Infrequent operations (like adding or removing roles) are slow, while frequent operations (like checking whether a user has a permission) are fast.
 

## Getting Started

Goperm is designed to be adapted to your own app, so it isn't quite a drop-in package. Here's what you need to do to get it up and running :

 1. Get dependencies. Goperm's only non-core dependency is [github.com/jmoiron/sqlx](https://github.com/jmoiron/sqlx). The tests also use [github.com/stretchr/testify/assert](https://github.com/stretchr/testify).
 2. Create the tables. Goperm uses five tables to do its thing. Migrations in the style of [github.com/mattes/migrate](https://github.com/mattes/migrate)are provided for Postgres. Still need to port these to MySql and possibly other stores.
 3. Set the database. The vanilla package relies on an unset instance of "database/sql". You need to pass it a configure instance from your application.
 4. Set the user. The package defines a dummy User interface with primary key typed as interface{}. You should adapt that those dummy settings to match your application.
 
 
 
 
 
 
 
 