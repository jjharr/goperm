CREATE TABLE permissions (
  permission_slug TEXT NOT NULL,
  permission_name TEXT NOT NULL DEFAULT '',
  permission_description TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMP NOT NULL,
  deleted_at TIMESTAMP NOT NULL DEFAULT '0001-01-01 00:00:00',

  PRIMARY KEY(permission_slug)
);
