package org.sid.authservice.sec.filters;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.json.JsonMapper;
import org.sid.authservice.sec.JwtUtil;
import org.sid.authservice.sec.entities.AppUser;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.bind.annotation.CrossOrigin;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;


public class JWTAuthenticationFilter  extends UsernamePasswordAuthenticationFilter {
    private AuthenticationManager authenticationManager;

    public JWTAuthenticationFilter(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }


    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        AppUser appUser=new AppUser();
        appUser.setUsername(request.getParameter("username"));
        appUser.setPassword(request.getParameter("password"));
        return authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(appUser.getUsername(),appUser.getPassword())
        );

    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        User authenticatedUser= (User) authResult.getPrincipal();
        Algorithm algorithm=Algorithm.HMAC256(JwtUtil.SECRET);
        String jwtAccessToken= JWT
                .create()
                .withSubject(authenticatedUser.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis()+JwtUtil.ACCESS_TOKEN_TIMEOUT))
                .withIssuer(request.getRequestURL().toString())
                .withClaim("roles",authenticatedUser.getAuthorities()
                        .stream().map(a->a.getAuthority()).collect(Collectors.toList()))
                .sign(algorithm);

        String jwtRefreshToken= JWT
                .create()
                .withSubject(authenticatedUser.getUsername())
                .withExpiresAt(new Date(System.currentTimeMillis()+JwtUtil.REFRESH_TOKEN_TIMEOUT))
                .withIssuer(request.getRequestURL().toString())
                .sign(algorithm);
        Map<String,String> idToken=new HashMap<>();
        idToken.put("Access_Token",jwtAccessToken);
        idToken.put("Refresh_Token",jwtRefreshToken);
        response.setContentType("application/json");
        new ObjectMapper().writeValue(response.getOutputStream(),idToken);

    }
}
