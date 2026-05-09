package com.ewallet.apigateway.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;

@Component
public class JwtUtil {

    @Value("${jwt.secret}")
    private String secret;

    private SecretKey getSigningKey() {
        return Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
    }


    public Claims getAllClaims(String token) {
        return Jwts.parser()
                .verifyWith(getSigningKey())
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }


    public boolean isTokenValid(String token) {
        try {
            getAllClaims(token);
            return true;
        } catch (Exception e) {
            return false;
        }
    }


    public String extractEmail(String token) {
        return getAllClaims(token).getSubject();
    }


    public String extractRole(String token) {
        return getAllClaims(token).get("role", String.class);
    }
}