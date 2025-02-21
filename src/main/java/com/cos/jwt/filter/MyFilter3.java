package com.cos.jwt.filter;

import jakarta.servlet.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.io.IOException;
import java.io.PrintWriter;

public class MyFilter3 implements Filter {

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {
        HttpServletRequest request = (HttpServletRequest) servletRequest;
        HttpServletResponse response = (HttpServletResponse) servletResponse;

        // 토큰 : cos, id, pw 정상적으로 들어와서 로그인이 완료되면 토큰을 만들어주고 그걸 응답을 해준다.
        // 요청할 때 마다 header에 Authorization에 value값으로 토큰을 가지고 오겠죠?
        // 그때 토큰이 넘어오면 이 토큰이 내가 만든 토큰이 맞는지만 검증만 하면 됨. (RSA, HS256)
        if(request.getMethod().equals("POST")){
            System.out.println("POST 요청됨");
            String headerAuth = request.getHeader("Authorization");
            System.out.println("headerAuth = " + headerAuth);
            System.out.println("필터1");

            if(headerAuth.equals("cos")){
                filterChain.doFilter(request, response);
            } else {
                PrintWriter out = response.getWriter();
                out.println("인증안됨");
            }
        }
    }
}
