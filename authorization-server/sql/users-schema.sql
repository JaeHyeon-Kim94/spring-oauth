SET FOREIGN_KEY_CHECKS = 0;
CREATE TABLE IF NOT EXISTS tb_user
(
    `id`              BIGINT(20)   NOT NULL AUTO_INCREMENT,
    `tb_role_id`      VARCHAR(100) NULL DEFAULT 'U_1',
    `user_name`       VARCHAR(45)   NOT NULL,
    `password`        VARCHAR(300)  NOT NULL,
    `name`            VARCHAR(100) NOT NULL,
    `nickname`        VARCHAR(45)  NOT NULL,
    `phone`           VARCHAR(100),
    `email`           VARCHAR(100),
    `birth`           DATE,
    `reg_date` TIMESTAMP    NULL DEFAULT CURRENT_TIMESTAMP,
    `mod_date` TIMESTAMP    NULL     DEFAULT NULL,

    PRIMARY KEY (`id`),
    UNIQUE INDEX `nickname_unique` (`nickname` ASC),
    INDEX `idx_fk_tb_user_tb_role_id` (`tb_role_id` ASC),
    CONSTRAINT `fk_tb_user_tb_role_id`
        FOREIGN KEY (`tb_role_id`)
            REFERENCES  `tb_role` (`id`)
            ON DELETE RESTRICT
);

CREATE TABLE IF NOT EXISTS tb_role
(
    `id`                VARCHAR(100) NOT NULL,
    `parent_id`         VARCHAR(100) NULL DEFAULT NULL,
    `role_desc`         VARCHAR(45) NULL DEFAULT NULL,
    `role_name`         VARCHAR(45) NOT NULL,

    PRIMARY KEY (`id`),
    INDEX `idx_fk_tb_role_tb_role_parent_id` (`parent_id` ASC),
    CONSTRAINT `fk_tb_role_tb_role_id`
        FOREIGN KEY (`parent_id`)
            REFERENCES  `tb_role` (`id`)
            ON DELETE SET NULL
);

CREATE TABLE IF NOT EXISTS  `tb_resource`
(
    `id`                    VARCHAR(100) NOT NULL,
    `tb_role_id`            VARCHAR(100) NOT NULL,
    `resource_type`         VARCHAR(45) NOT NULL,
    `resource_value`        VARCHAR(200) NOT NULL,
    `resource_http_method`  VARCHAR(45) NOT NULL,

    PRIMARY KEY (`id`),
    INDEX `idx_fk_tb_resource_tb_role_id` (`tb_role_id` ASC),
    CONSTRAINT `fk_tb_resource_tb_role_id`
        FOREIGN KEY (`tb_role_id`)
            REFERENCES `tb_role` (`id`)
            ON DELETE RESTRICT
);
SET FOREIGN_KEY_CHECKS = 1;