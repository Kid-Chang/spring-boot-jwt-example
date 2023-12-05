package com.cos.jwt.config.auth;

import com.cos.jwt.model.User;
import java.util.ArrayList;
import java.util.Collection;
import lombok.Data;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

@Data
@RequiredArgsConstructor
public class PrincipalDetails implements UserDetails {

    private final User user;

    // getAuthorities() 메서드는 해당 유저의 권한을 리턴해줘야 한다.
    // forEach() 메서드는 람다식을 사용하여 각각의 권한을 GrantedAuthority 타입으로 authorities에 넣어준다.
    // ()-> r 은 람다식으로 r을 리턴해준다.
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        Collection<GrantedAuthority> authorities = new ArrayList<>();
        user.getRoleList().forEach(r -> {
            authorities.add(() -> r);
        });

        return authorities;
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
