use fenix;
CREATE TABLE IF NOT EXISTS Users(
    userID varint PRIMARY KEY,
    username text,
    password blob,
    email text,
    settings map,
    token text,
    usernameHash varint,
    createdAt time,
    verified boolean
);
