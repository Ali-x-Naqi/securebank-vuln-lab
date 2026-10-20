-- SecureBank schema.
-- Passwords are stored in plaintext ON PURPOSE for this teaching lab, so the
-- advanced SQL-injection stage can demonstrate dumping real usernames and
-- passwords. (The README notes that a real safe build would also hash them
-- with a password-specific algorithm such as bcrypt; that is a separate
-- concern from the injection fix, which is parameterised queries.)

DROP TABLE IF EXISTS transactions;
DROP TABLE IF EXISTS messages;
DROP TABLE IF EXISTS users;

CREATE TABLE users (
  id            INT AUTO_INCREMENT PRIMARY KEY,
  username      VARCHAR(32) UNIQUE NOT NULL,
  password      VARCHAR(128) NOT NULL,
  full_name     VARCHAR(100) NOT NULL,
  email         VARCHAR(128) NOT NULL,
  account_number VARCHAR(16) NOT NULL,
  balance       DECIMAL(12,2) NOT NULL DEFAULT 0
);

CREATE TABLE transactions (
  id          INT AUTO_INCREMENT PRIMARY KEY,
  user_id     INT NOT NULL,
  description VARCHAR(255) NOT NULL,
  amount      DECIMAL(12,2) NOT NULL,
  created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE messages (
  id         INT AUTO_INCREMENT PRIMARY KEY,
  user_id    INT NOT NULL,
  body       TEXT NOT NULL,
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY (user_id) REFERENCES users(id)
);
