package io.oauth.client.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import io.oauth.client.model.CustomOAuth2AuthorizedClient;
import io.oauth.utils.JwtUtils;
import org.springframework.dao.DataRetrievalFailureException;
import org.springframework.dao.DuplicateKeyException;
import org.springframework.jdbc.core.ArgumentPreparedStatementSetter;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.PreparedStatementSetter;
import org.springframework.jdbc.core.SqlParameterValue;
import org.springframework.jdbc.support.lob.DefaultLobHandler;
import org.springframework.jdbc.support.lob.LobCreator;
import org.springframework.jdbc.support.lob.LobHandler;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.JdbcOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.user.DefaultOidcUser;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;
import java.sql.*;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;

public class CustomJdbcOAuth2AuthorizedClientService extends JdbcOAuth2AuthorizedClientService implements OAuth2AuthorizedClientService {

    private static final String COLUMN_NAMES =
            "client_registration_id, "
            + "principal_name, "
            + "access_token_type, "
            + "access_token_value, "
            + "access_token_issued_at, "
            + "access_token_expires_at, "
            + "access_token_scopes, "
            + "refresh_token_value, "
            + "refresh_token_issued_at, "
            + "refresh_token_expires_at,"
            + "id_token_value, "
            + "id_token_issued_at, "
            + "id_token_expires_at ";

    private static final String TABLE_NAME = "oauth2_authorized_client";

    private static final String PK_FILTER = "client_registration_id = ? AND principal_name = ?";

    private static final String LOAD_AUTHORIZED_CLIENT_SQL = "SELECT " + COLUMN_NAMES
            + " FROM " + TABLE_NAME
            + " WHERE " + PK_FILTER;

    private static final String SAVE_AUTHORIZED_CLIENT_SQL = "INSERT INTO " + TABLE_NAME
            + " (" + COLUMN_NAMES + ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

    private static final String REMOVE_AUTHORIZED_CLIENT_SQL = "DELETE FROM " + TABLE_NAME + " WHERE " + PK_FILTER;

    private static final String UPDATE_AUTHORIZED_CLIENT_SQL = "UPDATE " + TABLE_NAME
            + " SET access_token_type = ?, access_token_value = ?, access_token_issued_at = ?,"
            + " access_token_expires_at = ?, access_token_scopes = ?,"
            + " refresh_token_value = ?, refresh_token_issued_at = ?, refresh_token_expires_at = ?, "
            + " id_token_value = ?, id_token_issued_at= ?, id_token_expires_at = ?"
            + " WHERE " + PK_FILTER;


    public CustomJdbcOAuth2AuthorizedClientService(JdbcOperations jdbcOperations, ClientRegistrationRepository clientRegistrationRepository) {
        this(jdbcOperations, clientRegistrationRepository, new DefaultLobHandler());
    }

    public CustomJdbcOAuth2AuthorizedClientService(JdbcOperations jdbcOperations, ClientRegistrationRepository clientRegistrationRepository, LobHandler lobHandler) {
        super(jdbcOperations, clientRegistrationRepository, lobHandler);
        CustomOAuth2AuthorizedClientRowMapper customOAuth2AuthorizedClientRowMapper
                = new CustomOAuth2AuthorizedClientRowMapper(clientRegistrationRepository);
        customOAuth2AuthorizedClientRowMapper.setLobHandler(lobHandler);
        super.authorizedClientRowMapper = customOAuth2AuthorizedClientRowMapper;
        super.authorizedClientParametersMapper = new CustomOAuth2AuthorizedClientParametersMapper();
    }

    @Override
    public <T extends OAuth2AuthorizedClient> T loadAuthorizedClient(String clientRegistrationId, String principalName) {
        Assert.hasText(clientRegistrationId, "clientRegistrationId cannot be empty");
        Assert.hasText(principalName, "principalName cannot be empty");
        SqlParameterValue[] parameters = new SqlParameterValue[] {
                new SqlParameterValue(Types.VARCHAR, clientRegistrationId),
                new SqlParameterValue(Types.VARCHAR, principalName) };
        PreparedStatementSetter pss = new ArgumentPreparedStatementSetter(parameters);
        List<OAuth2AuthorizedClient> result = this.jdbcOperations.query(LOAD_AUTHORIZED_CLIENT_SQL, pss,
                this.authorizedClientRowMapper);
        return !result.isEmpty() ? (T) result.get(0) : null;
    }

    @Override
    public void saveAuthorizedClient(OAuth2AuthorizedClient authorizedClient, Authentication principal) {
        Assert.notNull(authorizedClient, "authorizedClient cannot be null");
        Assert.notNull(principal, "principal cannot be null");
        boolean existsAuthorizedClient = null != this.loadAuthorizedClient(
                authorizedClient.getClientRegistration().getRegistrationId(), principal.getName());
        if (existsAuthorizedClient) {
            updateAuthorizedClient(authorizedClient, principal);
        }
        else {
            try {
                insertAuthorizedClient(authorizedClient, principal);
            }
            catch (DuplicateKeyException ex) {
                updateAuthorizedClient(authorizedClient, principal);
            }
        }
    }

    @Override
    public void removeAuthorizedClient(String clientRegistrationId, String principalName) {
        Assert.hasText(clientRegistrationId, "clientRegistrationId cannot be empty");
        Assert.hasText(principalName, "principalName cannot be empty");
        SqlParameterValue[] parameters = new SqlParameterValue[] {
                new SqlParameterValue(Types.VARCHAR, clientRegistrationId),
                new SqlParameterValue(Types.VARCHAR, principalName) };
        PreparedStatementSetter pss = new ArgumentPreparedStatementSetter(parameters);
        this.jdbcOperations.update(REMOVE_AUTHORIZED_CLIENT_SQL, pss);
    }

    private void insertAuthorizedClient(OAuth2AuthorizedClient authorizedClient, Authentication principal){
        List<SqlParameterValue> parameters = this.authorizedClientParametersMapper
                .apply(new OAuth2AuthorizedClientHolder(authorizedClient, principal));
        try (LobCreator lobCreator = this.lobHandler.getLobCreator()) {
            PreparedStatementSetter pss = new CustomJdbcOAuth2AuthorizedClientService.LobCreatorArgumentPreparedStatementSetter(lobCreator,
                    parameters.toArray());
            this.jdbcOperations.update(SAVE_AUTHORIZED_CLIENT_SQL, pss);
        }
    }

    private void updateAuthorizedClient(OAuth2AuthorizedClient authorizedClient, Authentication principal) {
        List<SqlParameterValue> parameters = this.authorizedClientParametersMapper
                .apply(new OAuth2AuthorizedClientHolder(authorizedClient, principal));
        SqlParameterValue clientRegistrationIdParameter = parameters.remove(0);
        SqlParameterValue principalNameParameter = parameters.remove(0);
        parameters.add(clientRegistrationIdParameter);
        parameters.add(principalNameParameter);
        try (LobCreator lobCreator = this.lobHandler.getLobCreator()) {
            PreparedStatementSetter pss = new CustomJdbcOAuth2AuthorizedClientService.LobCreatorArgumentPreparedStatementSetter(lobCreator,
                    parameters.toArray());
            this.jdbcOperations.update(UPDATE_AUTHORIZED_CLIENT_SQL, pss);
        }
    }


    public static class CustomOAuth2AuthorizedClientRowMapper extends OAuth2AuthorizedClientRowMapper{

        public CustomOAuth2AuthorizedClientRowMapper(ClientRegistrationRepository clientRegistrationRepository) {
            super(clientRegistrationRepository);
        }

        @Override
        public CustomOAuth2AuthorizedClient mapRow(ResultSet rs, int rowNum) throws SQLException {

            String clientRegistrationId = rs.getString("client_registration_id");
            ClientRegistration clientRegistration
                    = clientRegistrationRepository.findByRegistrationId(clientRegistrationId);
            if (clientRegistration == null) {
                throw new DataRetrievalFailureException(
                        "The ClientRegistration with id '" + clientRegistrationId + "' exists in the data source, "
                                + "however, it was not found in the ClientRegistrationRepository.");
            }

            //AccessToken
            OAuth2AccessToken.TokenType tokenType = null;
            if(OAuth2AccessToken.TokenType.BEARER.getValue().equalsIgnoreCase(rs.getString("access_token_type"))){
                tokenType = OAuth2AccessToken.TokenType.BEARER;
            }
            String tokenValue = new String(lobHandler.getBlobAsBytes(rs, "access_token_value"),
                    StandardCharsets.UTF_8);
            Instant issuedAt = rs.getTimestamp("access_token_issued_at").toInstant();
            Instant expiresAt = rs.getTimestamp("access_token_expires_at").toInstant();
            Set<String> scopes = Collections.emptySet();
            String accessTokenScopes = rs.getString("access_token_scopes");
            if (accessTokenScopes != null) {
                scopes = StringUtils.commaDelimitedListToSet(accessTokenScopes);
            }
            OAuth2AccessToken accessToken = new OAuth2AccessToken(tokenType, tokenValue, issuedAt, expiresAt, scopes);

            //RefreshToken
            OAuth2RefreshToken refreshToken = null;
            byte[] refreshTokenValue = this.lobHandler.getBlobAsBytes(rs, "refresh_token_value");
            if (refreshTokenValue != null) {
                tokenValue = new String(refreshTokenValue, StandardCharsets.UTF_8);
                issuedAt = null;
                expiresAt = null;

                Timestamp refreshTokenIssuedAt = rs.getTimestamp("refresh_token_issued_at");
                if (refreshTokenIssuedAt != null) {
                    issuedAt = refreshTokenIssuedAt.toInstant();
                }
                Timestamp refreshTokenExpiresAt = rs.getTimestamp("refresh_token_expires_at");
                if (refreshTokenExpiresAt != null){
                    expiresAt = refreshTokenExpiresAt.toInstant();
                }
                refreshToken = new OAuth2RefreshToken(tokenValue, issuedAt, expiresAt);
            }

            OidcIdToken idToken = null;
            byte[] idTokenValue = this.lobHandler.getBlobAsBytes(rs, "id_token_value");
            if (idTokenValue != null){
                tokenValue = new String(idTokenValue, StandardCharsets.UTF_8);
                issuedAt = null;
                expiresAt = null;

                Timestamp idTokenIssuedAt = rs.getTimestamp("id_token_issued_at");
                if(idTokenIssuedAt != null){
                    issuedAt = idTokenIssuedAt.toInstant();
                }
                Timestamp idTokenExpiresAt = rs.getTimestamp("id_token_expires_at");
                if(idTokenExpiresAt != null){
                    expiresAt = idTokenExpiresAt.toInstant();
                }

                try {
                    idToken = new OidcIdToken(tokenValue, issuedAt, expiresAt, JwtUtils.getClaims(tokenValue));
                } catch (JsonProcessingException e) {
                    throw new RuntimeException(e);
                }
            }

            String principalName = rs.getString("principal_name");

            return new CustomOAuth2AuthorizedClient(clientRegistration, principalName, accessToken, refreshToken, idToken);
        }

    }

    public static class CustomOAuth2AuthorizedClientParametersMapper
           extends OAuth2AuthorizedClientParametersMapper {

        @Override
        public List<SqlParameterValue> apply(OAuth2AuthorizedClientHolder authorizedClientHolder) {
            OAuth2AuthorizedClient authorizedClient = authorizedClientHolder.getAuthorizedClient();
            Authentication principal = authorizedClientHolder.getPrincipal();
            ClientRegistration clientRegistration = authorizedClient.getClientRegistration();
            OAuth2AccessToken accessToken = authorizedClient.getAccessToken();
            OAuth2RefreshToken refreshToken = authorizedClient.getRefreshToken();



            //RegistrationId, PrincipalName, AccessToken (type, value, iat, exp)
            List<SqlParameterValue> parameters = new ArrayList<>();
            parameters.add(new SqlParameterValue(Types.VARCHAR, clientRegistration.getRegistrationId()));
            parameters.add(new SqlParameterValue(Types.VARCHAR, principal.getName()));

            parameters.add(new SqlParameterValue(Types.VARCHAR, accessToken.getTokenType().getValue()));
            parameters.add(new SqlParameterValue(Types.BLOB, accessToken.getTokenValue().getBytes(StandardCharsets.UTF_8)));
            parameters.add(new SqlParameterValue(Types.TIMESTAMP, Timestamp.from(accessToken.getIssuedAt())));
            parameters.add(new SqlParameterValue(Types.TIMESTAMP, Timestamp.from(accessToken.getExpiresAt())));

            //AccessToken Scopes
            String accessTokenScopes = null;
            if (!CollectionUtils.isEmpty(accessToken.getScopes())) {
                accessTokenScopes = StringUtils.collectionToDelimitedString(accessToken.getScopes(), ",");
            }
            parameters.add(new SqlParameterValue(Types.VARCHAR, accessTokenScopes));


            //RefreshToken (value, iat, exp)
            byte[] refreshTokenValue = null;
            Timestamp refreshTokenIssuedAt = null;
            Timestamp refreshTokenExpriesAt = null;

            if (refreshToken != null) {
                refreshTokenValue = refreshToken.getTokenValue().getBytes(StandardCharsets.UTF_8);
                if (refreshToken.getIssuedAt() != null) {
                    refreshTokenIssuedAt = Timestamp.from(refreshToken.getIssuedAt());
                }
                if(refreshToken.getExpiresAt() != null){
                    refreshTokenExpriesAt = Timestamp.from(refreshToken.getExpiresAt());
                }
            }
            parameters.add(new SqlParameterValue(Types.BLOB, refreshTokenValue));
            parameters.add(new SqlParameterValue(Types.TIMESTAMP, refreshTokenIssuedAt));
            parameters.add(new SqlParameterValue(Types.TIMESTAMP, refreshTokenExpriesAt));


            //IdToken (value, iat, exp)
            OidcIdToken idToken = null;
            byte[] idTokenValue = null;
            Timestamp idTokenIssuedAt = null;
            Timestamp idTokenExpiresAt = null;

            if (principal.getPrincipal() instanceof OidcUser){
                idToken = ((DefaultOidcUser)principal.getPrincipal()).getIdToken();
                idTokenValue = idToken.getTokenValue().getBytes(StandardCharsets.UTF_8);
                if(idToken != null && idToken.getIssuedAt() != null){
                    idTokenIssuedAt = Timestamp.from(idToken.getIssuedAt());
                }
                if(idToken != null && idToken.getExpiresAt() != null){
                    idTokenExpiresAt = Timestamp.from(idToken.getExpiresAt());
                }
            }
            parameters.add(new SqlParameterValue(Types.BLOB, idTokenValue));
            parameters.add(new SqlParameterValue(Types.TIMESTAMP, idTokenIssuedAt));
            parameters.add(new SqlParameterValue(Types.TIMESTAMP, idTokenExpiresAt));


            return parameters;
        }
    }

    private static final class LobCreatorArgumentPreparedStatementSetter extends ArgumentPreparedStatementSetter {

        protected final LobCreator lobCreator;

        private LobCreatorArgumentPreparedStatementSetter(LobCreator lobCreator, Object[] args) {
            super(args);
            this.lobCreator = lobCreator;
        }

        @Override
        protected void doSetValue(PreparedStatement ps, int parameterPosition, Object argValue) throws SQLException {
            if (argValue instanceof SqlParameterValue) {
                SqlParameterValue paramValue = (SqlParameterValue) argValue;
                if (paramValue.getSqlType() == Types.BLOB) {
                    if (paramValue.getValue() != null) {
                        Assert.isInstanceOf(byte[].class, paramValue.getValue(),
                                "Value of blob parameter must be byte[]");
                    }
                    byte[] valueBytes = (byte[]) paramValue.getValue();
                    this.lobCreator.setBlobAsBytes(ps, parameterPosition, valueBytes);
                    return;
                }
            }
            super.doSetValue(ps, parameterPosition, argValue);
        }

    }
}
