package io.oauth.authorizationserver.repository;

import io.oauth.authorizationserver.domain.User;
import org.springframework.stereotype.Repository;

@Repository
public class UserRepositoryMybatis implements UserRepository{

    private final UserMapper userMapper;

    public UserRepositoryMybatis(UserMapper userMapper) {
        this.userMapper = userMapper;
    }

    @Override
    public User findByUsername(String username) {
        return userMapper.findByUsername(username);
    }

    @Override
    public User save(User user) {
        userMapper.save(user);
        return user;
    }

    @Override
    public boolean isDuplicated(String type, String value) {
        return userMapper.isDuplicate(type, value);
    }
}
