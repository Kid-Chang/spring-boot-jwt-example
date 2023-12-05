package com.cos.jwt.config.auth;

import com.cos.jwt.model.User;
import com.cos.jwt.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

// /login 요청시 동작을 함.
@Service
@RequiredArgsConstructor
public class PrincipalDetailsService implements UserDetailsService {


    private final UserRepository userRepository;
    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        System.out.println("PrincipalDetailsService : 진입");
        User user = userRepository.findByUsername(username);
        if(user == null) {
            System.out.println("유저네임이 존재하지 않습니다. : "+username);
            throw new UsernameNotFoundException("유저네임이 존재하지 않습니다. : "+username);
        }
        System.out.println("PrincipalDetailsService : 유저 찾음-> "+ user);
        // session.setAttribute("loginUser", user);
        return new PrincipalDetails(user);
    }
}
