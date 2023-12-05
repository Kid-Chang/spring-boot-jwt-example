package com.cos.jwt.config.jwt;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.cos.jwt.config.auth.PrincipalDetails;
import com.cos.jwt.model.User;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;
import lombok.AllArgsConstructor;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

// 스프링시큐리티에서 UsernamePasswordAuthenticationFilter 가 있음.
// /login 요청해서 username, password 전송하면 (post)
// UsernamePasswordAuthenticationFilter 동작을 함.
// 그러면 PrincipalDetailsService 가 호출되고
// loadUserByUsername() 함수가 실행됨.
// PrincipalDetails 객체를 세션에 담고 (권한관리를 위해)
// 그 다음 요청부터는 UsernamePasswordAuthenticationFilter 가
// 세션을 관리함.
// 근데 formLogin() 을 disable() 하면
// UsernamePasswordAuthenticationFilter 가 작동을 안함.
// 그래서
// JwtAuthenticationFilter 를 만들어서
// Security 로직에 등록함.

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {



    private final AuthenticationManager authenticationManager;


    // /login 요청을 하면 로그인 시도를 위해서 실행되는 함수
    // UsernamePasswordAuthenticationFilter 가 /login 요청을 가로채서
    // 로그인 시도를 함.
    // 그리고 해당 필터를 거치면 attemptAuthentication() 함수가 실행됨.

    // AuthenticationManager 로 로그인 시도를 하면
    // PrincipalDetailsService 가 호출되고 loadUserByUsername() 함수가 실행됨.
    // 그리고 PrincipalDetails 객체를 세션에 담고
    // JWT 토큰을 만들어서 응답해주면 됨.

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
        throws AuthenticationException {

        System.out.println("JwtAuthenticationFilter : 진입");

        // request에 있는 username과 password를 파싱해서 자바 Object로 받기
        ObjectMapper om = new ObjectMapper();
        User loginRequestDto = null;
        try {
            loginRequestDto = om.readValue(request.getInputStream(), User.class);
        } catch (Exception e) {
            e.printStackTrace();
        }

        System.out.println("JwtAuthenticationFilter : "+loginRequestDto);

        // 유저네임패스워드 토큰 생성
        UsernamePasswordAuthenticationToken authenticationToken =
            new UsernamePasswordAuthenticationToken(
                loginRequestDto.getUsername(),
                loginRequestDto.getPassword());

        System.out.println("JwtAuthenticationFilter : 토큰생성완료");

        // authenticate() 함수가 호출 되면 인증 프로바이더가 유저 디테일 서비스의
        // loadUserByUsername(토큰의 첫번째 파라메터) 를 호출하고
        // UserDetails를 리턴받아서 토큰의 두번째 파라메터(credential)과
        // UserDetails(DB값)의 getPassword()함수로 비교해서 동일하면
        // Authentication 객체를 만들어서 필터체인으로 리턴해준다.

        // Tip: 인증 프로바이더의 디폴트 서비스는 UserDetailsService 타입
        // Tip: 인증 프로바이더의 디폴트 암호화 방식은 BCryptPasswordEncoder
        // 결론은 인증 프로바이더에게 알려줄 필요가 없음.
        Authentication authentication =
            authenticationManager.authenticate(authenticationToken);

        System.out.println("JwtAuthenticationFilter : 인증완료");

        PrincipalDetails principalDetailis = (PrincipalDetails) authentication.getPrincipal();
        System.out.println("Authentication : "+principalDetailis.getUser().getUsername());
        return authentication;
    }

    // attemptAuthentication() 실행 후 인증이 정상적으로 되었으면 successfulAuthentication() 함수가 실행됨.
    // JWT 토큰을 만들어서 request 요청한 사용자에게 JWT 토큰을 response 해주면 됨.
    @Override
    protected void successfulAuthentication(HttpServletRequest request,
        HttpServletResponse response, FilterChain chain, Authentication authResult)
        throws IOException, ServletException {
        System.out.println("successfulAuthentication 실행됨 : 인증이 완료되었다는 뜻임");

        PrincipalDetails principalDetails = (PrincipalDetails) authResult.getPrincipal();

        // RSA 방식은 아니고 Hash 암호방식
        // 이 방식이 RSA보다 더 많이 사용됨?
        String jwtToken = JWT.create()
            .withSubject(principalDetails.getUsername())
            .withExpiresAt(new java.util.Date(System.currentTimeMillis() + 1000 * 60 *10)) // 1초 * 60 * 10 = 10분
            .withClaim("id", principalDetails.getUser().getId())
            .withClaim("username", principalDetails.getUser().getUsername())
            .sign(Algorithm.HMAC512("cos"));


        super.successfulAuthentication(request, response, chain, authResult);
    }
}







