package de.nalto.identityServer.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.annotation.Order;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.factory.PasswordEncoderFactories;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.JdbcUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;

import javax.sql.DataSource;

@Configuration
@EnableWebSecurity
public class SecurityConfig {

    @Bean
    public UserDetailsService userDetailsService(DataSource dataSource) {
        return new JdbcUserDetailsManager(dataSource);
    }

    @Bean
    @Order(1)
    public SecurityFilterChain registerFilterChain(HttpSecurity http) throws Exception {
        http
            .securityMatcher("/register", "/error")
            .authorizeHttpRequests((auth) -> auth
                    .anyRequest().permitAll());
        return http.build();
    }

    @Bean
    public SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(auth -> auth
                .requestMatchers(
                        "/user",
                        "/user/**",
                        "/login",
                        "/users/**",
                        "/css/**")
                .permitAll()
                .anyRequest().authenticated())
            .formLogin((form) -> form.loginPage("/login").defaultSuccessUrl("/user/current").permitAll())
            .logout(logout -> logout.logoutUrl("/logout"));

        return http.build();
    }

    @Bean
    public PasswordEncoder passwordEncoder() {
        return PasswordEncoderFactories.createDelegatingPasswordEncoder();
    }
}