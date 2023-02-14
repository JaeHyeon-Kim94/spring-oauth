CREATE TABLE oauth2_authorization (
                                      id varchar(100) NOT NULL
                                  , registered_client_id varchar(100) NOT NULL
                                  , principal_name varchar(200) NOT NULL
                                  , authorization_grant_type varchar(100) NOT NULL
                                  , attributes blob DEFAULT NULL
                                  , state varchar(500) DEFAULT NULL
                                  , authorization_code_value blob DEFAULT NULL
                                  , authorization_code_issued_at timestamp DEFAULT NULL
                                  , authorization_code_expires_at timestamp DEFAULT NULL
                                  , authorization_code_metadata blob DEFAULT NULL
                                  , access_token_value blob DEFAULT NULL
                                  , access_token_issued_at timestamp DEFAULT NULL
                                  , access_token_expires_at timestamp DEFAULT NULL
                                  , access_token_metadata blob DEFAULT NULL
                                  , access_token_type varchar(100) DEFAULT NULL,
                                   access_token_scopes varchar(1000) DEFAULT NULL
                                  , oidc_id_token_value blob DEFAULT NULL
                                  , oidc_id_token_issued_at timestamp DEFAULT NULL
                                  , oidc_id_token_expires_at timestamp DEFAULT NULL
                                  , oidc_id_token_metadata blob DEFAULT NULL
                                  , refresh_token_value blob DEFAULT NULL
                                  , refresh_token_issued_at timestamp DEFAULT NULL
                                  , refresh_token_expires_at timestamp DEFAULT NULL
                                  , refresh_token_metadata blob DEFAULT NULL
                                  , PRIMARY KEY (id)
);