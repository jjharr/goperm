CREATE TABLE users__roles (
  user_id UUID NOT NULL,
  role_slug TEXT NOT NULL,
  created_at TIMESTAMP NOT NULL,
  deleted_at TIMESTAMP NOT NULL DEFAULT '0001-01-01 00:00:00',

  PRIMARY KEY(user_id,role_slug)
);
