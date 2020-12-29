package org.sid.authservice.sec.web;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.Data;
import org.sid.authservice.sec.JwtUtil;
import org.sid.authservice.sec.dao.RoleUserForm;
import org.sid.authservice.sec.entities.AppRole;
import org.sid.authservice.sec.entities.AppUser;
import org.sid.authservice.sec.service.AccountService;
import org.springframework.data.rest.core.annotation.RepositoryRestResource;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.*;
import java.util.stream.Collectors;

@CrossOrigin("*")
@RestController
public class AccountRestController {
    private AccountService accountService;

    public AccountRestController(AccountService accountService) {
        this.accountService = accountService;
    }
    @GetMapping(path = "/users")
    //@PreAuthorize("hasAuthority('USER')")
    public List<AppUser> appUsers() {
        return accountService.listUsers();
    }
    @GetMapping(path = "/roles")
    //@PreAuthorize("hasAuthority('USER')")
    public List<AppRole> appRoles() {
        return accountService.listRoles();
    }
    @PostMapping(path = "/users")
    //@PreAuthorize("hasAuthority('ADMIN')")
    public AppUser saveUser(@RequestBody AppUser appUser) {
        return accountService.addNewUser(appUser);
    }
    @PostMapping(path = "/roles")
    //@PreAuthorize("hasAuthority('ADMIN')")
    public AppRole saveRole(@RequestBody AppRole appRole) {
        return accountService.addNewRole(appRole);
    }
    @PostMapping(path = "/addRoleToUser")
    //@PreAuthorize("hasAuthority('ADMIN')")
    public void addRoleToUser(@RequestBody RoleUserForm roleUserForm) {
        accountService.addRoleToUser(roleUserForm.getUsername(), roleUserForm.getRolename());
    }

    @GetMapping(path = "/refreshToken")
    public void refreshToken(HttpServletRequest request, HttpServletResponse response){
        String authToken = request.getHeader(JwtUtil.AUTH_HEADER);
        if (authToken != null && authToken.startsWith(JwtUtil.HEADER_PREFIX)) {
            try {
                String jwtRefreshToken = authToken.substring(JwtUtil.HEADER_PREFIX.length());
                Algorithm algorithm = Algorithm.HMAC256(JwtUtil.SECRET);
                JWTVerifier jwtVerifier = JWT.require(algorithm).build();
                DecodedJWT decodedJWT = jwtVerifier.verify(jwtRefreshToken);
                String username = decodedJWT.getSubject();
                //revocation du token je verifie si il y a un chngemen donc je relead
                AppUser appUser= accountService.loadUserByUserName(username);
                //create accessToken
                String jwtAccessToken= JWT
                        .create()
                        .withSubject(appUser.getUsername())
                        .withExpiresAt(new Date(System.currentTimeMillis()+JwtUtil.ACCESS_TOKEN_TIMEOUT))
                        .withIssuer(request.getRequestURL().toString())
                        .withClaim("roles",appUser.getAppRoles().stream().map(a->a.getRoleName()).collect(Collectors.toList()))
                        .sign(algorithm);
               Map<String,String> idToken= new HashMap<>();
                idToken.put("Access_Token",jwtAccessToken);
                idToken.put("Refresh_Token",jwtRefreshToken);
               // return idToken;
                response.setContentType("application/json");
                new ObjectMapper().writeValue(response.getOutputStream(),idToken);
            }
            catch (Exception e){
                //ca peut etre une exception dateExpire ou autre
                throw  new RuntimeException(e.getMessage());
            }
        }
        else{
            throw new RuntimeException("Refresh Token Required");
        }

    }
}

