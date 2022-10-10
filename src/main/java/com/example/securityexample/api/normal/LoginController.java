package com.example.securityexample.api.normal;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import com.example.securityexample.security.config.UserDetailsServiceImpl;

@RestController
@RequestMapping("/api/v1/login")
public class LoginController {

  @Autowired
  private UserDetailsServiceImpl userDetailsService;

  @GetMapping()
  public String get() {

    String string = "Custom 接口返回的数据";

    // Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

    // UserDetails userDetails = (UserDetails) authentication.getPrincipal();

    UserDetails userDetails = userDetailsService.loadUserByUsername("user");

    // 登录成功后，需要更新security登陆用户对象
    UsernamePasswordAuthenticationToken AuthenticationToken =
        new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
    SecurityContextHolder.getContext().setAuthentication(AuthenticationToken);


    System.out.print("打印 name: " + userDetails.getUsername());

    return string + userDetails.getUsername();
  }
}
