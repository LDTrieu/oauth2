package com.example.authserver;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
public class SecurityConfig {
@Bean
	public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
http
    .authorizeHttpRequests(authorize ->
        authorize.mvcMatchers("/.well-known/jwks.json").permitAll()
            .antMatchers("/assets/**", "/login").permitAll()
            .anyRequest().authenticated()
    )
;
    // .oauth2Login(oauth2Login ->
    //     oauth2Login
    //         .loginPage("/login")
    // );

		return http.build();
	}
}
