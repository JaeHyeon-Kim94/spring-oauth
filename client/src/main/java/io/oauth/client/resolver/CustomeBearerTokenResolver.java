package io.oauth.client.resolver;

import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.server.resource.BearerTokenError;
import org.springframework.security.oauth2.server.resource.BearerTokenErrors;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class CustomeBearerTokenResolver implements BearerTokenResolver {

    private static final Pattern authorizationPattern = Pattern.compile("^Bearer (?<token>[a-zA-Z0-9-._~+/]+=*)$",
            Pattern.CASE_INSENSITIVE);

    private static final String REDIRECT_ATTRIBUTE_FLASH_MAP = "org.springframework.web.servlet.DispatcherServlet.INPUT_FLASH_MAP";


    private final OAuth2AuthorizedClientService oAuth2AuthorizedClientService;

    public CustomeBearerTokenResolver(OAuth2AuthorizedClientService oAuth2AuthorizedClientService) {
        this.oAuth2AuthorizedClientService = oAuth2AuthorizedClientService;
    }
    @Override
    public String resolve(HttpServletRequest request) {
        return resolveFromCookie(request);
    }

    private String resolveFromCookie(HttpServletRequest request){
        Cookie[] cookies = request.getCookies();
        if(cookies == null) return null;
        String idTokenValue = null;
        for (Cookie cookie : cookies) {
            if(cookie.getName().equals("o_id")){
                idTokenValue = cookie.getValue();
            }
        }
        if(idTokenValue == null) return null;

        return matchesWithPattern(idTokenValue);
    }

    private String matchesWithPattern(String idTokenValue) {
        Matcher matcher = authorizationPattern.matcher("Bearer "+idTokenValue);
        if(!matcher.matches()){
            BearerTokenError error = BearerTokenErrors.invalidToken("Bearer token is malformed");
            throw new OAuth2AuthenticationException(error);
        }
        return matcher.group("token");
    }

}
