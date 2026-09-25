package com.ota.securify;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
public class SecurityConfig {
    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                // 1. Tắt CSRF (vì REST API dùng JWT là stateless, không dùng session cookie)
                .csrf(AbstractHttpConfigurer::disable)

                // 2. Tắt chế độ quản lý Session (chuẩn cho Stateless JWT)
                .sessionManagement(session ->
                        session.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )

                // 3. Phân quyền request
                .authorizeHttpRequests(auth -> auth
                        // Cho phép truy cập tự do vào các API auth (đăng ký, đăng nhập)
                        .requestMatchers("/api/v1/auth/**").permitAll()
                        // Bất kỳ request nào khác đều bắt buộc phải xác thực
                        .anyRequest().authenticated()
                )

                // 4. Tắt form login giao diện mặc định của Spring Security
                .formLogin(AbstractHttpConfigurer::disable)
                .httpBasic(AbstractHttpConfigurer::disable);

        return http.build();
    }
}
