package io.oauth.authorizationserver.domain;

import lombok.EqualsAndHashCode;
import lombok.Getter;
import lombok.Setter;
import lombok.ToString;

import java.time.LocalDate;
import java.time.LocalDateTime;

@Getter
@Setter
@ToString
@EqualsAndHashCode
public class User {

    private Long id;
    private String username;
    private String password;

    private String name;
    private String nickname;

    private String phone;
    private String email;

    private LocalDate birth;
    private LocalDateTime regDate;
    private LocalDateTime modDate;

}
