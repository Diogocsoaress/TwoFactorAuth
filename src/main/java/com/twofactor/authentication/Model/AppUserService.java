package com.twofactor.authentication.Model;

import com.eatthepath.otp.TimeBasedOneTimePasswordGenerator;
import org.apache.commons.codec.binary.Base32;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import javax.crypto.spec.SecretKeySpec;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.time.Instant;

@Service
public class AppUserService implements UserDetailsService {

    @Autowired
    private AppUserRepository repository;

    private final TimeBasedOneTimePasswordGenerator totpGenerator;

    public AppUserService(AppUserRepository repository) {
        this.repository = repository;
        try {
            // Inicializa o gerador TOTP
            this.totpGenerator = new TimeBasedOneTimePasswordGenerator();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Erro ao inicializar TOTP Generator", e);
        }
    }

    @Override
    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        return repository.findByUsername(username)
            .orElseThrow(() -> new UsernameNotFoundException("Utilizador não encontrado: " + username));
    }

    // Gera o OTP com a chave secreta
    public String generateOTP(String totpSecret) {
        try {
            // Descodifica a chave secreta como Base32
            Base32 base32 = new Base32();
            byte[] decodedKey = base32.decode(totpSecret);
            Key key = new SecretKeySpec(decodedKey, "HmacSHA1");

            // Gera o OTP
            Instant now = Instant.now();
            return String.valueOf(totpGenerator.generateOneTimePassword(key, now));
        } catch (Exception e) {
            throw new RuntimeException("Erro ao gerar TOTP", e);
        }
    }

    // Verificação OTP
    public boolean verifyOTP(String totpSecret, String providedOTP) {
        try {
            // Descodifica a chave secreta como Base32
            Base32 base32 = new Base32();
            byte[] decodedKey = base32.decode(totpSecret);
            Key key = new SecretKeySpec(decodedKey, "HmacSHA1");

            // Gera o OTP atual
            Instant now = Instant.now();
            String generatedOTP = String.valueOf(totpGenerator.generateOneTimePassword(key, now));

            // Compara o OTP fornecido com o gerado
            return generatedOTP.equals(providedOTP);
        } catch (Exception e) {
            throw new RuntimeException("Erro ao verificar TOTP", e);
        }
    }
}
