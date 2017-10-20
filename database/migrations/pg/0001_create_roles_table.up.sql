CREATE TABLE roles (
  role_slug TEXT NOT NULL,
  role_name TEXT NOT NULL DEFAULT '',
  role_description TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMP NOT NULL,
  deleted_at TIMESTAMP NOT NULL DEFAULT '0001-01-01 00:00:00',

  PRIMARY KEY(role_slug)
);
