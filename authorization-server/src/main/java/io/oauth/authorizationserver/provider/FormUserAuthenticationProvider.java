package io.oauth.authorizationserver.provider;

import io.oauth.authorizationserver.domain.User;
import io.oauth.authorizationserver.model.Principal;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
@Slf4j
public class FormUserAuthenticationProvider implements AuthenticationProvider {

    //DB 연동 전까지 임시.
    private static final Map<Long, User> tempUsers = new ConcurrentHashMap<>();

    private final PasswordEncoder passwordEncoder;
    private final UserDetailsService userDetailsService;

    public FormUserAuthenticationProvider(PasswordEncoder passwordEncoder, UserDetailsService userDetailsService) {
        this.passwordEncoder = passwordEncoder;
        this.userDetailsService = userDetailsService;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        UsernamePasswordAuthenticationToken token =
        (UsernamePasswordAuthenticationToken)authentication;

        String username = token.getName();
        String password = (String)token.getCredentials();

        Principal principal = (Principal) userDetailsService.loadUserByUsername(username);

        if(!passwordEncoder.matches(password, principal.getPassword())){
            throw new BadCredentialsException("Invalid id or password");
        }

        return new UsernamePasswordAuthenticationToken(principal, null, principal.getAuthorities());
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return UsernamePasswordAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
