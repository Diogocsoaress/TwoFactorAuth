package com.twofactor.authentication.Security.Filter;

import java.io.IOException;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;

import com.twofactor.authentication.Model.AppUser;
import com.twofactor.authentication.Model.UserStatus;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.web.filter.OncePerRequestFilter;

public class OTPValidationFilter extends OncePerRequestFilter {

    private final AntPathRequestMatcher otpRequestMatcher = new AntPathRequestMatcher("/verify-otp");

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {

        // Verifica se o pedido é para a página de verificação de OTP
        if (otpRequestMatcher.matches(request)) {
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

            // Log do estado da autenticação
            System.out.println("Autenticação atual: " + authentication);
            if (authentication != null) {
                System.out.println("Autoridades: " + authentication.getAuthorities());
            }

            // Verifica se o utilizador está autenticado e se o principal é válido
            if (authentication == null || !(authentication.getPrincipal() instanceof AppUser user)) {
                System.out.println("O utilizador não está autenticado ou principal está inválido.");
                response.sendRedirect("/req/login?error=not_authenticated");
                return;
            }

            // Verifica se o utilizador tem a autoridade PRE_OTP_VERIFIED
            boolean hasAuthority = authentication.getAuthorities().stream()
                .anyMatch(authority -> authority.getAuthority().equals("PRE_OTP_VERIFIED"));

            if (!hasAuthority) {
                System.out.println("O utilizador não possui a autoridade 'PRE_OTP_VERIFIED.'");
                response.sendRedirect("/req/login?error=invalid_authority");
                return;
            }

            // Verifica o estado do utilizador
            if (user.getStatus() != UserStatus.PRE_OTP_VERIFIED) {
                System.out.println("Estado do utilizador inválido: " + user.getStatus());
                response.sendRedirect("/req/login?error=invalid_status");
                return;
            }
        }

        // Prossegue com o fluxo de filtros se tudo estiver correto
        filterChain.doFilter(request, response);
    }
}
