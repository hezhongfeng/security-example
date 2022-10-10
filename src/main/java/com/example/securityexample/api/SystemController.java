package com.example.securityexample.api;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/system")
public class SystemController {
  @GetMapping()
  public String get() {

    String string = "Custom 接口返回的数据";

    Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

    UserDetails user = (UserDetails) authentication.getPrincipal();

    System.out.print("打印 name: " + user.getUsername());

    return string;
  }
}
