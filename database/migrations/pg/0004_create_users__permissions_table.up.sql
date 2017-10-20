CREATE TABLE users__permissions (
  user_id UUID NOT NULL,
  permission_slug TEXT NOT NULL,
  added_on_user BOOL NOT NULL DEFAULT FALSE, -- i.e. this permission was not added via a user role
  created_at TIMESTAMP NOT NULL,
  deleted_at TIMESTAMP NOT NULL DEFAULT '0001-01-01 00:00:00',

  PRIMARY KEY(user_id,permission_slug,added_on_user)
);
