package com.example.securityexample.security.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.access.AccessDeniedHandler;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

// 登录成功调取的接口
@Component
public class SiteAuthenticationSuccessHandler implements AuthenticationSuccessHandler {

  @Override
  public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
      FilterChain chain, Authentication authentication) throws IOException, ServletException {
    AuthenticationSuccessHandler.super.onAuthenticationSuccess(request, response, chain,
        authentication);
  }

  @Override
  public void onAuthenticationSuccess(HttpServletRequest httpServletRequest,
      HttpServletResponse httpServletResponse, Authentication authentication)
      throws IOException, ServletException {
    // log.info("用户：{} 登录成功", authentication.getName());
    // String token = jwtTokenManager.createToken(authentication);
    // httpServletResponse.getWriter().write(JSON.toJSONString(ResponseMessage.ok(token)));

    // 拿到上一步设置的所有权限
    // Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

    UserDetails user = (UserDetails) authentication.getPrincipal();

    System.out.println(user);

    // authentication.getAuthorities()

    System.out.print("登录成功了啊");
  }
}
