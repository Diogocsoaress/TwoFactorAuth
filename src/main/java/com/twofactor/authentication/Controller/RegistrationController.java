package com.twofactor.authentication.Controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.twofactor.authentication.Model.AppUser;
import com.twofactor.authentication.Model.AppUserRepository;
import com.twofactor.authentication.Utils.QRCodeUtil;
import com.twofactor.authentication.Utils.TOTPUtil;

@Controller
public class RegistrationController {

    @Autowired
    private AppUserRepository appUserRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @PostMapping("/req/signup")
    public String createUser(
        @RequestParam String username,
        @RequestParam String password,
        @RequestParam String email,
        Model model,
        RedirectAttributes redirectAttributes
    ) {
        // Validação dos campos
        if (username == null || username.isEmpty() || password == null || password.isEmpty() || email == null || email.isEmpty()) {
            redirectAttributes.addFlashAttribute("error", "Todos os campos são obrigatórios.");
            return "redirect:/req/signup";
        }

        // Verificação do username
        if (appUserRepository.findByUsername(username).isPresent()) {
            redirectAttributes.addFlashAttribute("error", "Username já está em uso.");
            return "redirect:/req/signup";
        }

        // Criação do user
        AppUser user = new AppUser();
        user.setUsername(username);
        user.setPassword(passwordEncoder.encode(password));
        user.setEmail(email);

        // Gera o secret
        String totpSecret = TOTPUtil.generateSecret();
        user.setTotpSecret(totpSecret);

        appUserRepository.save(user);

        // Gera o URL e o QR Code 
        String qrCodeUrl = TOTPUtil.generateTOTPURL(username, totpSecret, "authentication");
        String qrCodeImage = QRCodeUtil.generateQRCodeBase64(qrCodeUrl);

        model.addAttribute("qrCodeImage", qrCodeImage);
        model.addAttribute("qrCodeUrl", qrCodeUrl);

        return "show-qr-code";
    }

}

