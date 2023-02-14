package io.oauth.authorizationserver.provider;

import io.oauth.authorizationserver.domain.User;
import io.oauth.authorizationserver.model.Principal;
import io.oauth.authorizationserver.utils.DecryptUtils;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.interfaces.RSAPrivateKey;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
@Slf4j
public class FormUserAuthenticationProvider implements AuthenticationProvider {



    //DB 연동 전까지 임시.
    private static final Map<Long, User> tempUsers = new ConcurrentHashMap<>();

    private final PasswordEncoder passwordEncoder;
    private final UserDetailsService userDetailsService;
    private final KeyPair keyPair;

    public FormUserAuthenticationProvider(PasswordEncoder passwordEncoder, UserDetailsService userDetailsService, KeyPair keyPair) {
        this.passwordEncoder = passwordEncoder;
        this.userDetailsService = userDetailsService;
        this.keyPair = keyPair;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        UsernamePasswordAuthenticationToken token =
        (UsernamePasswordAuthenticationToken)authentication;

        String username = token.getName();
        String password = (String)token.getCredentials();

        try {
            RSAPrivateKey rsaPrivateKey = (RSAPrivateKey) keyPair.getPrivate();
            password = DecryptUtils.decryptValueRsa(rsaPrivateKey, password);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }

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
