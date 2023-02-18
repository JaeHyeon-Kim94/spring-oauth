package io.oauth.authorizationserver.model;

import io.oauth.authorizationserver.domain.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.SpringSecurityCoreVersion;
import org.springframework.security.core.userdetails.UserDetails;

import java.io.Serializable;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

public class Principal implements UserDetails, Serializable {
    private static final long serialVersionUID = SpringSecurityCoreVersion.SERIAL_VERSION_UID;
    private User user;
    private Map<String, Object> attributes = new HashMap<>();
    public Principal(User user) {
        this.user = user;

        attributes.put("fullName", user.getFullName());
        attributes.put("nickname", user.getNickname());
        attributes.put("phone", user.getPhone());
        attributes.put("email", user.getEmail());
        attributes.put("birth", user.getBirth().toString());
    }

    public Map<String, Object> getAttributes() {
        return this.attributes;
    }

    public Long getUserId(){ return user.getId(); }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Collections.emptySet();
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
}
