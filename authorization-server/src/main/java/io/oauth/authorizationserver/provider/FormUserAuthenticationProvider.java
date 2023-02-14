package io.oauth.authorizationserver.provider;

import io.oauth.authorizationserver.domain.User;
import io.oauth.authorizationserver.model.Principal;
import io.oauth.authorizationserver.utils.RSAUtil;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.servlet.http.HttpSession;
import java.io.UnsupportedEncodingException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
@Slf4j
public class FormUserAuthenticationProvider implements AuthenticationProvider {

    private static final String PRIVATE_KEY_NAME = "__RSA_WEB_Key_";

    private final ObjectFactory<HttpSession> httpSessionFactory;

    private final PasswordEncoder passwordEncoder;
    private final UserDetailsService userDetailsService;

    public FormUserAuthenticationProvider(PasswordEncoder passwordEncoder, UserDetailsService userDetailsService, ObjectFactory<HttpSession> httpSessionFactory) {
        this.passwordEncoder = passwordEncoder;
        this.userDetailsService = userDetailsService;
        this.httpSessionFactory = httpSessionFactory;
    }

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

        UsernamePasswordAuthenticationToken token =
        (UsernamePasswordAuthenticationToken)authentication;

        String username = token.getName();
        String password = (String)token.getCredentials();

        HttpSession session = httpSessionFactory.getObject();


        PrivateKey privateKey = (PrivateKey) session.getAttribute(PRIVATE_KEY_NAME);
        if(privateKey == null){
            throw new RuntimeException("암호화 비밀키 정보를 찾을 수 없음.");
        }
        session.removeAttribute(PRIVATE_KEY_NAME);


        try {
            password = RSAUtil.decryptValueRsa(privateKey, password);
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
