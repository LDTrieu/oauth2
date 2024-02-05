package com.example.authserver;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.NoOpPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

@EnableWebSecurity
@Configuration(proxyBeanMethods = false)
public class SecurityConfig {
    // @Bean
    // SecurityFilterChain configureSecurityFilterChain(HttpSecurity http) throws Exception {
    //     // allow any request
    //     http.authorizeRequests(authorizeRequests -> authorizeRequests.anyRequest().permitAll());
    //     // http
    //     // .authorizeHttpRequests(authorizeRequests -> authorizeRequests.anyRequest().authenticated())
    //     // .formLogin(Customizer.withDefaults());
        
    //     return http.build();
  // OAuth2AuthorizationEndpointFilter
    // OAuth2AuthorizationCodeRequestAuthenticationProvider
    // OidcUserInfoAuthenticationProvider
    // OAuth2TokenEndpointFilter;
    // OAuth2ClientAuthenticationFilter
    // OAuth2AuthorizationCodeAuthenticationProvider
    // OAuth2TokenIntrospectionAuthenticationProvider
    // }

    @Bean
    public PasswordEncoder passwordEncoder() {
        PasswordEncoder encoder =   NoOpPasswordEncoder.getInstance();
        return encoder;
    }
    

    // @Bean
    // public UserDetailsService users() {
        
    //     PasswordEncoder encoder = PasswordEncoderFactories.createDelegatingPasswordEncoder();
        
    //     UserDetails user = User.withUsername("minhto")
    //             .password(encoder.encode("minhto"))
    //             .roles("USER")
    //             .build();
        
    //     return new InMemoryUserDetailsManager(user);
        
    // }
// @Bean
// 	public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
// http
//     .authorizeHttpRequests(authorize ->
//         authorize.mvcMatchers("/.well-known/jwks.json").permitAll()
//             .antMatchers("/assets/**", "/login").permitAll()
//             .anyRequest().authenticated()
//     )
// ;
//     // .oauth2Login(oauth2Login ->
//     //     oauth2Login
//     //         .loginPage("/login")
//     // );

// 		return http.build();
// 	}
}
