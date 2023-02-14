package io.oauth.authorizationserver.repository;

import io.oauth.authorizationserver.domain.User;
import org.apache.ibatis.annotations.Mapper;

@Mapper
public interface UserMapper {

    boolean isDuplicate(String type, String value);

    User findById(Long id);

    User findByUsername(String username);

    void save(User user);

}
