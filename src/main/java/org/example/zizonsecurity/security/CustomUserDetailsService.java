package org.example.zizonsecurity.security;

import lombok.RequiredArgsConstructor;
import org.example.zizonsecurity.domain.User;
import org.example.zizonsecurity.repository.UserRepository;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;
import org.springframework.security.core.userdetails.User.UserBuilder;

@Service
@RequiredArgsConstructor
public class CustomUserDetailsService implements UserDetailsService {
    private final UserRepository userRepository;

    // UserBuilder를 사용해 UserDetails 객체를 생성
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userRepository.findByUsername(username);
        if(user == null) {
            throw new UsernameNotFoundException("사용자가 없습니다.");
        }
        UserBuilder userBuilder =  org.springframework.security.core.userdetails.User.withUsername(username);
        userBuilder.password(user.getPassword());
        userBuilder.roles(user.getRoles().stream().map(role -> role.getName()).toArray(String[]::new));

        return userBuilder.build();
    }
}
