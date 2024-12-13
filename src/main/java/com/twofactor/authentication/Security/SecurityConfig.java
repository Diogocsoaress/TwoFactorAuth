package com.twofactor.authentication.Security;

import java.util.List;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.twofactor.authentication.Model.AppUser;
import com.twofactor.authentication.Model.AppUserRepository;
import com.twofactor.authentication.Model.AppUserService;
import com.twofactor.authentication.Model.UserStatus;
import com.twofactor.authentication.Security.Filter.OTPValidationFilter;

import lombok.RequiredArgsConstructor;

@Configuration
@RequiredArgsConstructor
@EnableWebSecurity
public class SecurityConfig {

    private final AppUserService appUserService;
    private final AppUserRepository appUserRepository;

    //Codificador da Password
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    //Codifica a Password do User
    @Bean
    public AuthenticationProvider authenticationProvider() {
        DaoAuthenticationProvider provider = new DaoAuthenticationProvider();
        provider.setUserDetailsService(appUserService);
        provider.setPasswordEncoder(passwordEncoder());
        return provider;
    }

    @Bean
    public AuthenticationSuccessHandler customSuccessHandler() {
        return (request, response, authentication) -> {
            AppUser user = (AppUser) authentication.getPrincipal();

            // Atualiza o estado do utilizador
            if (user.getStatus() == UserStatus.NEW_USER) {
                user.setStatus(UserStatus.PRE_OTP_VERIFIED);
                appUserRepository.save(user);

                // Adiciona a autoridade
                Authentication updatedAuth = new UsernamePasswordAuthenticationToken(
                    authentication.getPrincipal(),
                    authentication.getCredentials(),
                    List.of(new SimpleGrantedAuthority("PRE_OTP_VERIFIED"))
                );
                SecurityContextHolder.getContext().setAuthentication(updatedAuth);
                System.out.println("Autenticação atualizada para PRE_OTP_VERIFIED.");
            }

            // Redireciona de acordo com o estado
            switch (user.getStatus()) {
                case PRE_OTP_VERIFIED -> response.sendRedirect("/verify-otp");
                case OTP_VERIFIED -> {
                    // Atualiza o estado para PRE_OTP_VERIFIED ao refazer login
                    user.setStatus(UserStatus.PRE_OTP_VERIFIED);
                    appUserRepository.save(user);
            
                    // Atualiza as permissões
                    Authentication updatedAuth = new UsernamePasswordAuthenticationToken(
                        authentication.getPrincipal(),
                        authentication.getCredentials(),
                        List.of(new SimpleGrantedAuthority("PRE_OTP_VERIFIED"))
                    );
                    SecurityContextHolder.getContext().setAuthentication(updatedAuth);
                    response.sendRedirect("/verify-otp");
                }
                default -> response.sendRedirect("/req/login?error=invalid_status");
            }
        };
    }

    //Fluxo da aplicação
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        return http
            .csrf().disable()
            .addFilterAfter(new OTPValidationFilter(), UsernamePasswordAuthenticationFilter.class) 
            .formLogin(login -> login
                .loginPage("/req/login").permitAll()
                .successHandler(customSuccessHandler())
                .failureUrl("/req/login?error=invalid_credentials")
            )
            .exceptionHandling(exceptions -> exceptions
                .accessDeniedPage("/req/login?accessDenied=true")
            )
            .logout(logout -> logout
                .logoutUrl("/logout")
                .logoutSuccessUrl("/req/login?logout=true")
                .invalidateHttpSession(true) 
                .deleteCookies("JSESSIONID") 
            )
            //Acesso às páginas conforme o estado do utilizador
            .authorizeHttpRequests(auth -> auth
                .requestMatchers("/req/signup", "/css/**", "/js/**", "/images/**", "/req/login").permitAll()
                .requestMatchers("/req/login", "/css/**", "/js/**", "/images/**", "/verify-otp").hasAuthority("PRE_OTP_VERIFIED")
                .requestMatchers("/verify-otp", "/css/**", "/js/**", "/images/**", "/index").hasAuthority("OTP_VERIFIED")
                .anyRequest().authenticated()
            )
            .authenticationProvider(authenticationProvider())
            .build();
    }

}
