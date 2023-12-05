package com.cos.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.config.auth.PrincipalDetails;
import com.cos.jwt.model.User;
import com.cos.jwt.repository.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.www.BasicAuthenticationFilter;

// 시큐리티가 filter를 가지고 있는데 그 필터중에 BasicAuthenticationFilter 라는 것이 있음.
// JWT토큰이 있던 없든 인증이나 권한이 필요한 특정 주소를 요청했을 때 위 필터를 무조건 타게 되어있음.
// 만약에 권한이나 인증이 필요한 주소가 아니라면 이 필터를 타지 않음.
// 예를 들어 /login이나 requestMatchers에 설정한 주소등?이 맞나?
// 아닌거 같기도 하고.. 그냥 인증이 필요한 주소를 요청했을 때 이 필터를 타게 됨.


public class JwtAuthorizationFilter extends BasicAuthenticationFilter {

    private UserRepository userRepository;

    public JwtAuthorizationFilter(
        AuthenticationManager authenticationManager, UserRepository userRepository) {
        super(authenticationManager);
        this.userRepository = userRepository;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response,
        FilterChain chain) throws IOException, ServletException {
        // super.doFilter가 바로 응답을 처리해버려 오류가 발생. 주석처리
//        super.doFilterInternal(request, response, chain);
        System.out.println("JwtAuthorizationFilter : 진입");

        String jwtHeader = request.getHeader(JwtProperties.HEADER_STRING);
        System.out.println("jwtHeader : " + jwtHeader);

        // header가 있는지 확인
        if (jwtHeader == null || !jwtHeader.startsWith(JwtProperties.TOKEN_PREFIX)) {
            chain.doFilter(request, response);
            // 밑의 내용들을 진행하지않고 다시 필터를 타게 해야함.
            return;
        }

        // jwt 토큰을 검증해서 정상적인 사용자인지 확인
        String token = request.getHeader(JwtProperties.HEADER_STRING)
            .replace(JwtProperties.TOKEN_PREFIX, "");
        // "Bearere "를 빼고 토큰만 가져옴.

        String username = JWT.require(Algorithm.HMAC512(JwtProperties.SECRET)).build().verify(token)
            .getClaim("username").asString();

        if (username != null) {
            // 서명이 정상적으로 됨.
            // 서명이 정상적으로 될 때만 getClaim()을 사용할 수 있음.
            User userEntity = userRepository.findByUsername(username);

            PrincipalDetails principalDetails = new PrincipalDetails(userEntity);

            // Jwt 토큰 서명을 통해서 서명이 정상이면 Authentication 객체를 만들어준다.
            Authentication authentication = new UsernamePasswordAuthenticationToken(
                principalDetails, null, principalDetails.getAuthorities());

            // 강제로 시큐리티의 세션(SecurityContextHolder)에 접근하여 Authentication 객체를 저장.
            SecurityContextHolder.getContext().setAuthentication(authentication);

            chain.doFilter(request, response);
        }


    }
}
