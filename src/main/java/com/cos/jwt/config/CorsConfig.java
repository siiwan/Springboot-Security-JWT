package com.cos.jwt.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import org.springframework.web.filter.CorsFilter;

@Configuration
public class CorsConfig {

    @Bean
    public CorsFilter corsFilter() {
        UrlBasedCorsConfigurationSource soure = new UrlBasedCorsConfigurationSource();
        CorsConfiguration config = new CorsConfiguration();
        config.setAllowCredentials(true); //내서버가 응답을 할 때 json을 자바스크립에서 처리할 수 있게 할지를 설정하는 것
        config.addAllowedOrigin("*");   //모든 ip에 응당을 허용.
        config.addAllowedHeader("*");   //모든 header에 응답을 허용.
        config.addAllowedMethod("*");   //모든 post,get,put,delete,petch 허용.
        soure.registerCorsConfiguration("api/**", config);
        return new CorsFilter(soure);
    }
}
