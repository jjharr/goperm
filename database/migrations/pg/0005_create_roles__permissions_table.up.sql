CREATE TABLE roles__permissions (
  role_slug TEXT NOT NULL,
  permission_slug TEXT NOT NULL,
  created_at TIMESTAMP NOT NULL,
  deleted_at TIMESTAMP NOT NULL DEFAULT '0001-01-01 00:00:00',

  PRIMARY KEY(role_slug,permission_slug)
);
