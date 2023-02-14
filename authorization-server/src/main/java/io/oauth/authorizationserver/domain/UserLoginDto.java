package io.oauth.authorizationserver.domain;

import lombok.Getter;
import lombok.Setter;
import org.hibernate.validator.constraints.Length;

import javax.validation.constraints.NotBlank;
import javax.validation.constraints.Pattern;

@Getter
@Setter
public class UserLoginDto {

    @NotBlank
    @Pattern(regexp = "^(\\w)*$")
    @Length(min=3, max=10)
    private String username;

    @NotBlank
    private String password;



}
