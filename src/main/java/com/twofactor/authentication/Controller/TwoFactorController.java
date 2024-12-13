package com.twofactor.authentication.Controller;

import java.security.Principal;
import java.util.ArrayList;
import java.util.Collection;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.twofactor.authentication.Model.AppUser;
import com.twofactor.authentication.Model.AppUserRepository;
import com.twofactor.authentication.Model.UserStatus;
import com.twofactor.authentication.Utils.TOTPUtil;

import jakarta.servlet.http.HttpServletRequest;

@Controller
public class TwoFactorController {

    private final AppUserRepository appUserRepository;

    public TwoFactorController(AppUserRepository appUserRepository) {
        this.appUserRepository = appUserRepository;
    }

    @GetMapping("/verify-otp")
    public String showVerifyOtpPage(Model model) {
        if (!model.containsAttribute("error")) {
            model.addAttribute("error", null);
        }
        return "verify-otp"; 
    }

    @PostMapping("/verify-otp")
    public String verifyOtp(@RequestParam String providedOTP, Principal principal, 
                            RedirectAttributes redirectAttributes, HttpServletRequest request) {
        try {
            String username = principal.getName();
            AppUser user = appUserRepository.findByUsername(username)
                .orElseThrow(() -> new IllegalStateException("Utilizador não encontrado."));

            
            if (TOTPUtil.verifyOTP(user.getTotpSecret(), providedOTP)) {
                // Atualiza o estado do utilizador para OTP_VERIFIED
                user.setStatus(UserStatus.OTP_VERIFIED);
                appUserRepository.save(user);

                // Atualiza as autoridades para incluir OTP_VERIFIED
                Authentication currentAuth = SecurityContextHolder.getContext().getAuthentication();
                Collection<GrantedAuthority> updatedAuthorities = new ArrayList<>(currentAuth.getAuthorities());
                updatedAuthorities.add(new SimpleGrantedAuthority("OTP_VERIFIED"));

                // Cria uma nova autenticação com as autoridades atualizadas
                Authentication newAuth = new UsernamePasswordAuthenticationToken(
                    currentAuth.getPrincipal(),
                    currentAuth.getCredentials(),
                    updatedAuthorities
                );

                // Define a nova autenticação no contexto de segurança
                SecurityContextHolder.getContext().setAuthentication(newAuth);

                // Adiciona a sessão ao contexto de segurança
                request.getSession().setAttribute("SPRING_SECURITY_CONTEXT", SecurityContextHolder.getContext());

                return "redirect:/index"; // Redireciona para a página principal após sucesso
            } else {
                redirectAttributes.addFlashAttribute("error", "Código OTP inválido. Tente novamente.");
                return "redirect:/verify-otp";
            }
        } catch (Exception e) {
            redirectAttributes.addFlashAttribute("error", "Erro inesperado: " + e.getMessage());
            return "redirect:/verify-otp";
        }
    }
}
