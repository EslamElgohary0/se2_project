
package com.ewallet.apigateway.filter;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.core.io.buffer.DataBuffer;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.time.LocalDateTime;
import java.util.HashMap;
import java.util.Map;

@Component
public class AuthenticationFilter
        extends AbstractGatewayFilterFactory<AuthenticationFilter.Config> {

    @Autowired
    private JwtUtil jwtUtil;

    private final ObjectMapper objectMapper = new ObjectMapper();

    public AuthenticationFilter() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            String authHeader = exchange.getRequest()
                    .getHeaders()
                    .getFirst(HttpHeaders.AUTHORIZATION);


            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                return writeErrorResponse(exchange.getResponse(),
                        HttpStatus.UNAUTHORIZED,
                        "لم يتم إرسال Token — أضف Authorization: Bearer {token} في الـ Header");
            }

            String token = authHeader.substring(7);


            if (!jwtUtil.isTokenValid(token)) {
                return writeErrorResponse(exchange.getResponse(),
                        HttpStatus.UNAUTHORIZED,
                        "الـ Token غير صالح أو منتهي الصلاحية — قم بتسجيل الدخول مرة أخرى");
            }


            try {
                Claims claims = jwtUtil.getAllClaims(token);
                String userEmail = claims.getSubject();
                String userRole  = claims.get("role", String.class);


                exchange = exchange.mutate()
                        .request(r -> r
                                .header("X-User-Email", userEmail != null ? userEmail : "")
                                .header("X-User-Role",  userRole  != null ? userRole  : "")
                        )
                        .build();
            } catch (Exception e) {

                return writeErrorResponse(exchange.getResponse(),
                        HttpStatus.UNAUTHORIZED,
                        "فشل في قراءة بيانات الـ Token");
            }

            return chain.filter(exchange);
        };
    }


    private Mono<Void> writeErrorResponse(
            org.springframework.http.server.reactive.ServerHttpResponse response,
            HttpStatus status,
            String message) {

        response.setStatusCode(status);
        response.getHeaders().setContentType(MediaType.APPLICATION_JSON);
        response.getHeaders().set(HttpHeaders.ACCESS_CONTROL_ALLOW_ORIGIN, "*");

        Map<String, Object> errorBody = new HashMap<>();
        errorBody.put("timestamp", LocalDateTime.now().toString());
        errorBody.put("status", status.value());
        errorBody.put("error", status.getReasonPhrase());
        errorBody.put("message", message);
        errorBody.put("path", "API Gateway");

        try {
            byte[] bytes = objectMapper.writeValueAsBytes(errorBody);
            DataBuffer buffer = response.bufferFactory().wrap(bytes);
            return response.writeWith(Mono.just(buffer));
        } catch (JsonProcessingException e) {
            return response.setComplete();
        }
    }

    public static class Config {

    }
}