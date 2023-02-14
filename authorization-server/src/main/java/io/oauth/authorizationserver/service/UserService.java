package io.oauth.authorizationserver.service;

import io.oauth.authorizationserver.domain.User;
import io.oauth.authorizationserver.repository.UserRepository;
import org.springframework.stereotype.Service;

@Service
public class UserService {

    private final UserRepository userRepository;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public User save(User user){
        return userRepository.save(user);
    }

    public boolean checkIsDuplicated(String type, String value) {
        return userRepository.isDuplicated(type, value);
    }
}
