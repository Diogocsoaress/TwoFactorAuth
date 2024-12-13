package com.twofactor.authentication.Utils;

import java.security.SecureRandom;
import de.taimos.totp.TOTP;
import org.apache.commons.codec.binary.Base32;
import org.apache.commons.codec.binary.Hex;

public class TOTPUtil {

    // Gera uma chave secreta em Base32
    public static String generateSecret() {
        SecureRandom random = new SecureRandom();
        byte[] bytes = new byte[10]; // 80 bits para TOTP
        random.nextBytes(bytes);
        return new Base32().encodeToString(bytes);
    }

    // Gera o URL compatível com o Google Authenticator
    public static String generateTOTPURL(String username, String secret, String appName) {
        return String.format(
            "otpauth://totp/%s:%s?secret=%s&issuer=%s",
            appName,
            username,
            secret,
            appName
        );
    }

    // Verifica o OTP gerado com o fornecido
    public static boolean verifyOTP(String secretBase32, String providedOTP) {
       
            // Descodifica o segredo Base32 para bytes
            Base32 base32 = new Base32();
            byte[] secretBytes = base32.decode(secretBase32);

            // Converte os bytes para HEX, que é o que o TOTP.getOTP espera
            String secretHex = Hex.encodeHexString(secretBytes);

            // Gera o OTP usando o segredo em HEX
            String generatedOTP = TOTP.getOTP(secretHex);

            // Compara o OTP gerado com o fornecido
            return generatedOTP.equals(providedOTP);
    }
    
}
