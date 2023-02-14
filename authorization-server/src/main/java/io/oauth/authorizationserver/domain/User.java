package io.oauth.authorizationserver.domain;

import lombok.*;

import java.time.LocalDate;
import java.time.LocalDateTime;

@Getter
@Setter
@ToString
@EqualsAndHashCode
@Builder
public class User {

    private Long id;
    private String username;
    private String password;

    private String fullName;
    private String nickname;

    private String phone;
    private String email;

    private LocalDate birth;
    private LocalDateTime regDate;
    private LocalDateTime modDate;

}
