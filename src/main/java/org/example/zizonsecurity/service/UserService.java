package org.example.zizonsecurity.service;

import lombok.RequiredArgsConstructor;
import org.example.zizonsecurity.domain.Role;
import org.example.zizonsecurity.domain.User;
import org.example.zizonsecurity.repository.RoleRepository;
import org.example.zizonsecurity.repository.UserRepository;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Collections;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final RoleRepository roleRepository;

    private final PasswordEncoder passwordEncoder;

    //회원가입
    @Transactional
    public User regisUser(User user) {
        // role 추가
        Role userRole = roleRepository.findByName("USER");
        user.setRoles(Collections.singleton(userRole));
        // password 암호화해서 넣어둬야 함
        user.setPassword(passwordEncoder.encode(user.getPassword()));

        return userRepository.save(user);
    }

    @Transactional(readOnly = true)
    public User findByUsername(String username) {
        return userRepository.findByUsername(username);
    }
}
