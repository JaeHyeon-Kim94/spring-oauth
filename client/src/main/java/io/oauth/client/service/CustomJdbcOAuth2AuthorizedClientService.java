package io.oauth.client.service;

import io.oauth.client.model.CustomOAuth2AuthorizedClient;
import org.springframework.jdbc.core.ArgumentPreparedStatementSetter;
import org.springframework.jdbc.core.JdbcOperations;
import org.springframework.jdbc.core.RowMapper;
import org.springframework.jdbc.core.SqlParameterValue;
import org.springframework.jdbc.support.lob.DefaultLobHandler;
import org.springframework.jdbc.support.lob.LobCreator;
import org.springframework.jdbc.support.lob.LobHandler;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.JdbcOAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.JdbcOAuth2AuthorizedClientService.OAuth2AuthorizedClientHolder;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClient;
import org.springframework.security.oauth2.client.OAuth2AuthorizedClientService;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2RefreshToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.util.Assert;
import org.springframework.util.CollectionUtils;
import org.springframework.util.StringUtils;

import java.nio.charset.StandardCharsets;
import java.sql.*;
import java.util.ArrayList;
import java.util.List;
import java.util.function.Function;

public class CustomJdbcOAuth2AuthorizedClientService extends JdbcOAuth2AuthorizedClientService implements OAuth2AuthorizedClientService {

    private static final String COLUMN_NAMES =
            "client_registration_id, "
            + "principal_name, "
            + "id_token_value"
            + "id_token_issued_at"
            + "id_token_expires_at"
            + "access_token_type, "
            + "access_token_value, "
            + "access_token_issued_at, "
            + "access_token_expires_at, "
            + "access_token_scopes, "
            + "refresh_token_value, "
            + "refresh_token_issued_at";

    private static final String TABLE_NAME = "oauth2_authorized_client";

    private static final String PK_FILTER = "client_registration_id = ? AND principal_name = ?";

    private static final String LOAD_AUTHORIZED_CLIENT_SQL = "SELECT " + COLUMN_NAMES
            + " FROM " + TABLE_NAME
            + " WHERE " + PK_FILTER;

    private static final String SAVE_AUTHORIZED_CLIENT_SQL = "INSERT INTO " + TABLE_NAME
            + " (" + COLUMN_NAMES + ") VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";

    private static final String REMOVE_AUTHORIZED_CLIENT_SQL = "DELETE FROM " + TABLE_NAME + " WHERE " + PK_FILTER;

    private static final String UPDATE_AUTHORIZED_CLIENT_SQL = "UPDATE " + TABLE_NAME
            + " SET access_token_type = ?, access_token_value = ?, access_token_issued_at = ?,"
            + " id_token_value = ?, id_token_issued_at= ?, id_token_expires_at = ?,"
            + " access_token_expires_at = ?, access_token_scopes = ?,"
            + " refresh_token_value = ?, refresh_token_issued_at = ?"
            + " WHERE " + PK_FILTER;

    protected RowMapper<CustomOAuth2AuthorizedClient> authorizedClientRowMapper;

    public CustomJdbcOAuth2AuthorizedClientService(JdbcOperations jdbcOperations, ClientRegistrationRepository clientRegistrationRepository) {
        this(jdbcOperations, clientRegistrationRepository, new DefaultLobHandler());
    }

    public CustomJdbcOAuth2AuthorizedClientService(JdbcOperations jdbcOperations, ClientRegistrationRepository clientRegistrationRepository, LobHandler lobHandler) {
        super(jdbcOperations, clientRegistrationRepository, lobHandler);
        CustomOAuth2AuthorizedClientRowMapper customOAuth2AuthorizedClientRowMapper
                = new CustomOAuth2AuthorizedClientRowMapper(clientRegistrationRepository);
        this.authorizedClientRowMapper = customOAuth2AuthorizedClientRowMapper;

    }

    @Override   //TODO
    public <T extends OAuth2AuthorizedClient> T loadAuthorizedClient(String clientRegistrationId, String principalName) {
        return null;
    }

    @Override   //TODO
    public void saveAuthorizedClient(OAuth2AuthorizedClient authorizedClient, Authentication principal) {

    }

    @Override   //TODO
    public void removeAuthorizedClient(String clientRegistrationId, String principalName) {

    }

    public static class CustomOAuth2AuthorizedClientRowMapper implements RowMapper<CustomOAuth2AuthorizedClient>{
        protected final ClientRegistrationRepository clientRegistrationRepository;

        protected LobHandler lobHandler = new DefaultLobHandler();

        public CustomOAuth2AuthorizedClientRowMapper(ClientRegistrationRepository clientRegistrationRepository) {
            Assert.notNull(clientRegistrationRepository, "clientRegistrationRepository cannot be null");
            this.clientRegistrationRepository = clientRegistrationRepository;
        }

        public final void setLobHandler(LobHandler lobHandler) {
            Assert.notNull(lobHandler, "lobHandler cannot be null");
            this.lobHandler = lobHandler;
        }


        @Override   //TODO
        public CustomOAuth2AuthorizedClient mapRow(ResultSet rs, int rowNum) throws SQLException {
            return null;
        }

    }

    public static class OAuth2AuthorizedClientParametersMapper
            implements Function<OAuth2AuthorizedClientHolder, List<SqlParameterValue>> {

        @Override
        public List<SqlParameterValue> apply(OAuth2AuthorizedClientHolder authorizedClientHolder) {
            CustomOAuth2AuthorizedClient authorizedClient = authorizedClientHolder.getAuthorizedClient();
            Authentication principal = authorizedClientHolder.getPrincipal();
            ClientRegistration clientRegistration = authorizedClient.getClientRegistration();
            OAuth2AccessToken accessToken = authorizedClient.getAccessToken();
            OAuth2RefreshToken refreshToken = authorizedClient.getRefreshToken();
            OidcIdToken idToken = authorizedClient.getIdToken();

            List<SqlParameterValue> parameters = new ArrayList<>();
            parameters.add(new SqlParameterValue(Types.VARCHAR, clientRegistration.getRegistrationId()));
            parameters.add(new SqlParameterValue(Types.VARCHAR, principal.getName()));
            parameters.add(new SqlParameterValue(Types.VARCHAR, accessToken.getTokenType().getValue()));
            parameters.add(
                    new SqlParameterValue(Types.BLOB, accessToken.getTokenValue().getBytes(StandardCharsets.UTF_8)));
            parameters.add(new SqlParameterValue(Types.TIMESTAMP, Timestamp.from(accessToken.getIssuedAt())));
            parameters.add(new SqlParameterValue(Types.TIMESTAMP, Timestamp.from(accessToken.getExpiresAt())));


            String accessTokenScopes = null;
            if (!CollectionUtils.isEmpty(accessToken.getScopes())) {
                accessTokenScopes = StringUtils.collectionToDelimitedString(accessToken.getScopes(), ",");
            }
            parameters.add(new SqlParameterValue(Types.VARCHAR, accessTokenScopes));

            byte[] refreshTokenValue = null;
            Timestamp refreshTokenIssuedAt = null;
            if (refreshToken != null) {
                refreshTokenValue = refreshToken.getTokenValue().getBytes(StandardCharsets.UTF_8);
                if (refreshToken.getIssuedAt() != null) {
                    refreshTokenIssuedAt = Timestamp.from(refreshToken.getIssuedAt());
                }
            }
            parameters.add(new SqlParameterValue(Types.BLOB, refreshTokenValue));
            parameters.add(new SqlParameterValue(Types.TIMESTAMP, refreshTokenIssuedAt));


            byte[] idTokenValue = null;
            Timestamp idTokenIssuedAt = null;
            Timestamp idTokenExpiresAt = null;

            if (idToken != null){
                idTokenValue = idToken.getTokenValue().getBytes(StandardCharsets.UTF_8);
                if(idToken.getIssuedAt() != null){
                    idTokenIssuedAt = Timestamp.from(idToken.getIssuedAt());
                }
                if(idToken.getExpiresAt() != null){
                    idTokenExpiresAt = Timestamp.from(idToken.getExpiresAt());
                }
            }

            parameters.add(
                    new SqlParameterValue(Types.BLOB, idTokenValue));
            parameters.add(new SqlParameterValue(Types.TIMESTAMP, idTokenIssuedAt));
            parameters.add(new SqlParameterValue(Types.TIMESTAMP, idTokenExpiresAt));


            return parameters;
        }

    }

    public static final class OAuth2AuthorizedClientHolder {

        private final CustomOAuth2AuthorizedClient authorizedClient;

        private final Authentication principal;


        public OAuth2AuthorizedClientHolder(CustomOAuth2AuthorizedClient authorizedClient, Authentication principal) {
            Assert.notNull(authorizedClient, "authorizedClient cannot be null");
            Assert.notNull(principal, "principal cannot be null");
            this.authorizedClient = authorizedClient;
            this.principal = principal;
        }


        public CustomOAuth2AuthorizedClient getAuthorizedClient() {
            return this.authorizedClient;
        }

        public Authentication getPrincipal() {
            return this.principal;
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
