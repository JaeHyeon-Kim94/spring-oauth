package io.oauth.client.entrypoint;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.oauth2.client.OAuth2AuthorizeRequest;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientManager;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.jwt.JwtValidationException;
import org.springframework.security.web.AuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Base64;
import java.util.Map;

@Component
public class OAuth2LoginAuthenticationEntrypoint implements AuthenticationEntryPoint {


    private final OAuth2AuthorizedClientService oAuth2AuthorizedClientService;
    private final OAuth2AuthorizedClientManager oauth2AuthorizedClientManager;

    public OAuth2LoginAuthenticationEntrypoint(OAuth2AuthorizedClientService oAuth2AuthorizedClientService, OAuth2AuthorizedClientManager oauth2AuthorizedClientManager) {
        this.oAuth2AuthorizedClientService = oAuth2AuthorizedClientService;
        this.oauth2AuthorizedClientManager = oauth2AuthorizedClientManager;
    }

    private ObjectMapper objectMapper = new ObjectMapper();

    @Override
    public void commence(HttpServletRequest request, HttpServletResponse response, AuthenticationException authException) throws IOException, ServletException {
        if(authException.getCause() instanceof JwtValidationException){
            getNewAccessToken(request, response);
        }
    }

    private void getNewAccessToken(HttpServletRequest request, HttpServletResponse response) throws IOException {

        Cookie[] cookies = request.getCookies();

        String idToken = null;
        String regId = null;

        for (Cookie cookie : cookies) {

            if(cookie.getName().equals("r_id")){
                regId = cookie.getValue();
            }else if(cookie.getName().equals("o_id")){
                idToken = cookie.getValue();
            }

        }

        if(!StringUtils.hasText(regId) || !StringUtils.hasText(idToken)){
            response.sendError(HttpServletResponse.SC_UNAUTHORIZED, "다시 로그인해주세요.");
        }

        Base64.Decoder decoder = Base64.getDecoder();

        idToken = new String(decoder.decode(idToken.split("\\.")[1]));
        Map map = objectMapper.readValue(idToken, Map.class);

        regId = new String(decoder.decode(regId));

        OAuth2AuthorizedClient authorizedClient
                = oAuth2AuthorizedClientService.loadAuthorizedClient(regId, (String) map.get("sub"));

        ClientRegistration clientRegistration = ClientRegistration.withClientRegistration(authorizedClient.getClientRegistration())
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .build();

        OAuth2AuthorizedClient oAuth2AuthorizedClient = new OAuth2AuthorizedClient(clientRegistration
                , authorizedClient.getPrincipalName()
                , authorizedClient.getAccessToken()
                , authorizedClient.getRefreshToken());

        OAuth2AuthorizeRequest oAuth2AuthorizeRequest = OAuth2AuthorizeRequest.withAuthorizedClient(oAuth2AuthorizedClient)
                .principal(authorizedClient.getPrincipalName())
                .attribute(HttpServletRequest.class.getName(), request)
                .attribute(HttpServletResponse.class.getName(), response)
                .build();

        OAuth2AuthorizedClient authorize = oauth2AuthorizedClientManager.authorize(oAuth2AuthorizeRequest);
    }
}
