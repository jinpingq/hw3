CREATE SCHEMA IF NOT EXISTS idm;

CREATE TABLE IF NOT EXISTS idm.token_status
(
    id          INT             NOT NULL PRIMARY KEY,
    value       VARCHAR(32)     NOT NULL
    );

CREATE TABLE IF NOT EXISTS idm.user_status
(
    id          INT             NOT NULL PRIMARY KEY,
    value       VARCHAR(32)     NOT NULL
    );

CREATE TABLE IF NOT EXISTS idm.role
(
    id                INT             NOT NULL PRIMARY KEY,
    name              VARCHAR(32)     NOT NULL,
    description       VARCHAR(128)    NOT NULL,
    precedence        INT             NOT NULL
    );

CREATE TABLE IF NOT EXISTS idm.user
(
    id                  INT            NOT NULL PRIMARY KEY AUTO_INCREMENT,
    email               VARCHAR(32)    NOT NULL UNIQUE,
    user_status_id      INT            NOT NULL,
    salt                VARCHAR(8)    NOT NULL,
    hashed_password     VARCHAR(88)   NOT NULL,
    FOREIGN KEY (user_status_id) REFERENCES idm.user_status (id)
    ON UPDATE CASCADE ON DELETE CASCADE
    );

CREATE TABLE IF NOT EXISTS idm.refresh_token
(
    id                  INT            NOT NULL PRIMARY KEY AUTO_INCREMENT,
    token               VARCHAR(36)    NOT NULL UNIQUE,
    user_id             INT            NOT NULL,
    token_status_id     INT            NOT NULL,
    expire_time         TIMESTAMP      NOT NULL,
    max_life_time       TIMESTAMP      NOT NULL,
    FOREIGN KEY (user_id) REFERENCES idm.user (id)
    ON UPDATE CASCADE ON DELETE CASCADE,
    FOREIGN KEY (token_status_id) REFERENCES idm.token_status (id)
    ON UPDATE CASCADE ON DELETE CASCADE
    );

CREATE TABLE IF NOT EXISTS idm.user_role
(
    user_id             INT            NOT NULL,
    role_id             INT            NOT NULL,
    PRIMARY KEY (user_id, role_id),
    FOREIGN KEY (user_id) REFERENCES idm.user (id)
    ON UPDATE CASCADE ON DELETE CASCADE,
    FOREIGN KEY (role_id) REFERENCES idm.role (id)
    ON UPDATE CASCADE ON DELETE CASCADE
    );