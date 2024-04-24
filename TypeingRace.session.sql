-- @block
CREATE TABLE User (
    id INT PRIMARY KEY AUTO_INCREMENT,
    username VARCHAR(255) NOT NULL,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- @block
SELECT * FROM User;

-- make a table for the session
-- @block
CREATE TABLE Session (
    id INT PRIMARY KEY AUTO_INCREMENT,
    User_id INT NOT NULL,
    session_key VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);