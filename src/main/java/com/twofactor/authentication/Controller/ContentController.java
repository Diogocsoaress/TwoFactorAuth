package com.twofactor.authentication.Controller;

import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class ContentController {

    @GetMapping("/req/login")
    public String login() {
        return "login";
    }

    @GetMapping("/req/signup")
    public String signup() {
        return "signup";
    }

    @GetMapping("/index")
    public String home() {
        System.out.println("A aceder ao index como: " + SecurityContextHolder.getContext().getAuthentication());

        return "index";
    }

    @GetMapping("/show-qr-code")
    public String showQRCode(Model model) {
            return "show-qr-code"; 
        }   
}
