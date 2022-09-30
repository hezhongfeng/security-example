package com.example.securityexample.api;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/custom")
// @PreAuthorize("@rbacAuthorityService.hasPermissions('custom')") // 必须具有 custom 权限才能访问
public class CustomController {

  @GetMapping()
  public String get() {

    String string = "Custom 接口返回的数据";

    return string;
  }
}
