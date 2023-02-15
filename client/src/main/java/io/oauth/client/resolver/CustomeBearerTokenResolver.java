package io.oauth.client.resolver;

import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.server.resource.BearerTokenError;
import org.springframework.security.oauth2.server.resource.BearerTokenErrors;
import org.springframework.security.oauth2.server.resource.web.BearerTokenResolver;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.StringUtils;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class CustomeBearerTokenResolver implements BearerTokenResolver {

    private static final Pattern authorizationPattern = Pattern.compile("^Bearer (?<token>[a-zA-Z0-9-._~+/]+=*)$",
            Pattern.CASE_INSENSITIVE);

    private static final String DEFAULT_REQUEST_URI = "/registered-client/*/member/*";

    private static final String REDIRECT_ATTRIBUTE_FLASH_MAP = "org.springframework.web.servlet.DispatcherServlet.INPUT_FLASH_MAP";


    private final OAuth2AuthorizedClientService oAuth2AuthorizedClientService;

    public CustomeBearerTokenResolver(OAuth2AuthorizedClientService oAuth2AuthorizedClientService) {
        this.oAuth2AuthorizedClientService = oAuth2AuthorizedClientService;
    }
    @Override
    public String resolve(HttpServletRequest request) {
        String idTokenValue = null;

        AntPathRequestMatcher antPathRequestMatcher = new AntPathRequestMatcher(DEFAULT_REQUEST_URI);
        if(antPathRequestMatcher.matches(request)){
            String uri = request.getRequestURI();
            String[] parts = uri.split("/");

            //oAuth2AuthorizedClientService.loadAuthorizedClient()
        }else{
            String idTokenFromCookie = resolveFromCookie(request);
            String idTokenFromRedirectAttributes = resolveFromFlashMap(request);

            idTokenValue = StringUtils.hasText(idTokenFromCookie) ? idTokenFromCookie : idTokenFromRedirectAttributes;
        }

        return idTokenValue;
    }

    private String resolveFromCookie(HttpServletRequest request){
        Cookie[] cookies = request.getCookies();
        if(cookies == null) return null;
        String idTokenValue = null;
        for (Cookie cookie : cookies) {
            if(cookie.getName().equals("o_id")){
                String tempValue = new String(Base64.getDecoder().decode(cookie.getValue().getBytes(StandardCharsets.UTF_8)));
                if(StringUtils.startsWithIgnoreCase(tempValue, "Bearer ")){
                    idTokenValue = tempValue;
                }
            }
        }
        if(idTokenValue == null) return null;

        return matchesWithPattern(idTokenValue);
    }

    private String resolveFromFlashMap(HttpServletRequest request) {

        Map<String, Object> flash = (Map<String, Object>) request.getAttribute(REDIRECT_ATTRIBUTE_FLASH_MAP);

        String idTokenValue = null;
        if(flash!=null && !flash.isEmpty()){
            Object value = flash.get("Authorization");
            idTokenValue = value == null ? null : (String)value;
        }

        if(idTokenValue == null) return null;

        return matchesWithPattern(idTokenValue);
    }


    private String matchesWithPattern(String idTokenValue) {
        Matcher matcher = authorizationPattern.matcher(idTokenValue);
        if(!matcher.matches()){
            BearerTokenError error = BearerTokenErrors.invalidToken("Bearer token is malformed");
            throw new OAuth2AuthenticationException(error);
        }
        return matcher.group("token");
    }

}
