CREATE TABLE IF NOT EXISTS tb_user
(
    `id`              BIGINT(20)   NOT NULL AUTO_INCREMENT,
    `user_name`       VARCHAR(45)   NOT NULL,
    `password`        VARCHAR(300)  NOT NULL,
    `name`            VARCHAR(100) NOT NULL,
    `nickname`        VARCHAR(45)  NOT NULL,
    `phone`           VARCHAR(100),
    `email`           VARCHAR(100),
    `birth`           DATE,
    `reg_date` TIMESTAMP    NULL DEFAULT CURRENT_TIMESTAMP,
    `mod_date` TIMESTAMP    NULL     DEFAULT NULL,
    PRIMARY KEY (`id`)
)