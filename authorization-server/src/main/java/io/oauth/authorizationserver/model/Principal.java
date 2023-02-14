package io.oauth.authorizationserver.model;

import io.oauth.authorizationserver.domain.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.core.oidc.OidcUserInfo;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.io.Serializable;
import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

public class Principal implements UserDetails, OAuth2User, OidcUser, Serializable {
    private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;
    private User user;
    private Set<GrantedAuthority> authorities;

    private Map<String, Object> attributes;

    private String nameAttributeKey;

    private OidcIdToken idToken;

    public Principal(User user) {
        this.user = user;
        setAttributesByUser(user);
    }

    public Principal(User user, Map<String, Object> attributes, Set<GrantedAuthority> authorities, String nameAttributeKey) {
        this.user = user;
        this.attributes = attributes;
        this.authorities = authorities;
        this.nameAttributeKey = nameAttributeKey;
    }

    public Principal(User user, Map<String, Object> attributes, Set<GrantedAuthority> authorities, OidcIdToken idToken) {
        this.user = user;
        this.attributes = attributes;
        this.authorities = authorities;
        this.idToken = idToken;
    }

    private void setAttributesByUser(User user) {
        this.attributes = new HashMap<>();
        attributes.put("fullName", user.getFullName());
        attributes.put("nickname", user.getNickname());
        attributes.put("phone", user.getPhone());
        attributes.put("email", user.getEmail());
        attributes.put("birth", user.getBirth().toString());
    }


    @Override
    public String getName() {
        return user.getFullName();
    }

    @Override
    public Map<String, Object> getAttributes() {
        return this.attributes;
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return this.authorities;
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public Map<String, Object> getClaims() {
        return attributes;
    }

    @Override
    public OidcUserInfo getUserInfo() {
        return new OidcUserInfo(attributes);
    }

    @Override
    public OidcIdToken getIdToken() {
        return idToken;
    }

    public Long getUserId(){ return user.getId(); }
}
