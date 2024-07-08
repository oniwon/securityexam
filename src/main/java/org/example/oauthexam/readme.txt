
CREATE TABLE social_user (
id BIGINT AUTO_INCREMENT PRIMARY KEY,
social_id VARCHAR(255) NOT NULL,
provider VARCHAR(255) NOT NULL,
username VARCHAR(255),
email VARCHAR(255),
avatar_url VARCHAR(255)
);

ALTER TABLE users
ADD COLUMN social_id VARCHAR(255),
ADD COLUMN provider VARCHAR(50);

CREATE TABLE social_login_info (
                                   id BIGINT AUTO_INCREMENT PRIMARY KEY,
                                   provider VARCHAR(255) NOT NULL,
                                   social_Id VARCHAR(255) NOT NULL,
                                   created_At TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                                   uuid VARCHAR(255) NOT NULL
);