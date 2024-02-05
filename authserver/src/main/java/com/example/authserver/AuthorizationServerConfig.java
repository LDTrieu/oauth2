package com.example.authserver;

import java.util.UUID;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.oauth2.server.resource.OAuth2ResourceServerConfigurer;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configuration.OAuth2AuthorizationServerConfiguration;
import org.springframework.security.oauth2.server.authorization.config.annotation.web.configurers.OAuth2AuthorizationServerConfigurer;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import com.example.authserver.jose.Jwks;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
@Configuration(proxyBeanMethods = false)
public class AuthorizationServerConfig {
@Bean
	public JWKSource<SecurityContext> jwkSource() {
		RSAKey rsaKey = Jwks.generateRsa();
		JWKSet jwkSet = new JWKSet(rsaKey);
		return (jwkSelector, securityContext) -> jwkSelector.select(jwkSet);
	}
	
	@Bean
	public JwtDecoder jwtDecoder(JWKSource<SecurityContext> jwkSource) {
		return OAuth2AuthorizationServerConfiguration.jwtDecoder(jwkSource);
	}

	
	@Bean
    @Order(Ordered.HIGHEST_PRECEDENCE)
    public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
 
        OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
                
        http.getConfigurer(OAuth2AuthorizationServerConfigurer.class).oidc(Customizer.withDefaults()).and().oauth2ResourceServer(OAuth2ResourceServerConfigurer::jwt)
		
				.exceptionHandling(e -> e
				.authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint("/login")));
        return http.build();
    }

	@Bean
	@Order(2)
	public SecurityFilterChain appSecurityFilterChain(HttpSecurity http) throws Exception {
		return http
				.formLogin(Customizer.withDefaults())
				.authorizeHttpRequests(authorize ->authorize.anyRequest().authenticated())
				.build();
		
	}
	@Bean
    public AuthorizationServerSettings authorizationServerSettings() {
        return AuthorizationServerSettings.builder()
                .issuer("http://localhost:8080")
                .build();
    }
	@Bean
public RegisteredClientRepository registeredClientRepository() {
  RegisteredClient c =  
    RegisteredClient.withId(UUID.randomUUID().toString())
    .clientId("client")
    .clientSecret("{bcrypt}$2a$10$jdJGhzsiIqYFpjJiYWMl/eKDOd8vdyQis2aynmFN0dgJ53XvpzzwC")
    .clientAuthenticationMethod(ClientAuthenticationMethod.CLIENT_SECRET_BASIC)
    .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
    .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
    .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
    .redirectUri("http://localhost:8080/authorized")
    .scope(OidcScopes.OPENID)
    .scope(OidcScopes.PROFILE)        
          .clientSettings(ClientSettings.builder()
                                .requireAuthorizationConsent(true).build())
    .build();
 
    return new InMemoryRegisteredClientRepository(c);
}
	//  @Bean
	// @Order(Ordered.HIGHEST_PRECEDENCE)
	// public SecurityFilterChain authorizationServerSecurityFilterChain(
	// 		HttpSecurity http, RegisteredClientRepository registeredClientRepository,
	// 		AuthorizationServerSettings authorizationServerSettings) throws Exception {

	// 	OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);
	// 	return http.build();
	// 		}

    // @Bean
	// @Order(Ordered.HIGHEST_PRECEDENCE)
	// public SecurityFilterChain authorizationServerSecurityFilterChain(
	// 		HttpSecurity http, RegisteredClientRepository registeredClientRepository,
	// 		AuthorizationServerSettings authorizationServerSettings) throws Exception {

	// 	OAuth2AuthorizationServerConfiguration.applyDefaultSecurity(http);

	// 	/*
	// 	 * This sample demonstrates the use of a public client that does not
	// 	 * store credentials or authenticate with the authorization server.
	// 	 *
	// 	 * The following components show how to customize the authorization
	// 	 * server to allow for device clients to perform requests to the
	// 	 * OAuth 2.0 Device Authorization Endpoint and Token Endpoint without
	// 	 * a clientId/clientSecret.
	// 	 *
	// 	 * CAUTION: These endpoints will not require any authentication, and can
	// 	 * be accessed by any client that has a valid clientId.
	// 	 *
	// 	 * It is therefore RECOMMENDED to carefully monitor the use of these
	// 	 * endpoints and employ any additional protections as needed, which is
	// 	 * outside the scope of this sample.
	// 	 */
	// 	DeviceClientAuthenticationConverter deviceClientAuthenticationConverter =
	// 			new DeviceClientAuthenticationConverter(
	// 					"/**" + authorizationServerSettings.getDeviceAuthorizationEndpoint());
	// 	DeviceClientAuthenticationProvider deviceClientAuthenticationProvider =
	// 			new DeviceClientAuthenticationProvider(registeredClientRepository);

	// 	// @formatter:off
	// 	http.getConfigurer(OAuth2AuthorizationServerConfigurer.class)
	// 		.deviceAuthorizationEndpoint(deviceAuthorizationEndpoint ->
	// 			deviceAuthorizationEndpoint.verificationUri("/activate")
	// 		)
	// 		.deviceVerificationEndpoint(deviceVerificationEndpoint ->
	// 			deviceVerificationEndpoint.consentPage(CUSTOM_CONSENT_PAGE_URI)
	// 		)
	// 		.clientAuthentication(clientAuthentication ->
	// 			clientAuthentication
	// 				.authenticationConverter(deviceClientAuthenticationConverter)
	// 				.authenticationProvider(deviceClientAuthenticationProvider)
	// 		)
	// 		.authorizationEndpoint(authorizationEndpoint ->
	// 			authorizationEndpoint.consentPage(CUSTOM_CONSENT_PAGE_URI))
	// 		.oidc(Customizer.withDefaults());	// Enable OpenID Connect 1.0
	// 	// @formatter:on

	// 	// @formatter:off
	// 	http
	// 		.exceptionHandling((exceptions) -> exceptions
	// 			.defaultAuthenticationEntryPointFor(
	// 				new LoginUrlAuthenticationEntryPoint("/login"),
	// 				new MediaTypeRequestMatcher(MediaType.TEXT_HTML)
	// 			)
	// 		)
	// 		.oauth2ResourceServer(oauth2ResourceServer ->
	// 			oauth2ResourceServer.jwt(Customizer.withDefaults()));
	// 	// @formatter:on
	// 	return http.build();
	// }
    // NimbusJwkSetEndpointFilter jwkSetEndpointFilter(JWKSource<SecurityContext> jwkSource) {
    //     return new NimbusJwkSetEndpointFilter(jwkSource);

    // }
//     @Bean
// public SecurityFilterChain authorizationServerSecurityFilterChain(HttpSecurity http) throws Exception {
// 	OAuth2AuthorizationServerConfigurer authorizationServerConfigurer =
// 		new OAuth2AuthorizationServerConfigurer();
// 	http.apply(authorizationServerConfigurer);

// 	authorizationServerConfigurer
// 		.authorizationServerMetadataEndpoint(authorizationServerMetadataEndpoint ->
// 			authorizationServerMetadataEndpoint
// 				.authorizationServerMetadataCustomizer(authorizationServerMetadataCustomizer));   

// 	return http.build();
// }
}
