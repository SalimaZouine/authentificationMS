package org.sid.authservice.sec;


import org.sid.authservice.sec.filters.JWTAuthenticationFilter;
import org.sid.authservice.sec.filters.JWTAuthorizationFilter;
import org.sid.authservice.sec.service.UserDetailsServiceImpl;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.bind.annotation.CrossOrigin;

@Configuration
@CrossOrigin("*")
@EnableWebSecurity
public class  SecurityConfig  extends WebSecurityConfigurerAdapter {
   private UserDetailsServiceImpl userDetailsService;

    public SecurityConfig(UserDetailsServiceImpl userDetailsService) {
        this.userDetailsService = userDetailsService;
    }

    @Override
    protected void configure(AuthenticationManagerBuilder auth) throws Exception {
        auth.userDetailsService(userDetailsService);
    }


    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();
        //http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
        //http.formLogin();
        http.headers().frameOptions().disable();
        //je dis a springsecurity que n'importe q requete va etre autorise
        http.authorizeRequests().anyRequest().permitAll();
        //http.authorizeRequests().antMatchers("/h2-console/**","/refreshToken/**").permitAll();
        //http.authorizeRequests().antMatchers(HttpMethod.GET,"/users/**").hasAnyAuthority("USER");
        //http.authorizeRequests().antMatchers(HttpMethod.POST,"/users/**").hasAnyAuthority("ADMIN");
        //http.authorizeRequests().antMatchers(HttpMethod.POST,"/roles/**").hasAnyAuthority("ADMIN");
        //http.authorizeRequests().antMatchers(HttpMethod.POST,"/addRoleToUser/**").hasAnyAuthority("ADMIN");
        //http.authorizeRequests().anyRequest().permitAll(); //j'autorise tt les ressources
        //http.addFilter(new JWTAuthenticationFilter(authenticationManagerBean()));
        //http.addFilterBefore(new JWTAuthorizationFilter(),UsernamePasswordAuthenticationFilter.class);
    }
    //Bean : cad je dois je peux l'injecter a n q moment
    @Override
    @Bean
    public AuthenticationManager authenticationManagerBean() throws Exception {
        //nous retourne l"objet de authenticationmanager de spring
        return super.authenticationManagerBean();}
}
