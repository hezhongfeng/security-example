package com.example.securityexample.security.config;

import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutFilter;


// 一般用户的 security config
@EnableWebSecurity
public class DefaultSecurityConfig {

	@Bean
	SecurityFilterChain defaultSecurityFilterChain(HttpSecurity http) throws Exception {

		// String[] antMatchersAnonymous = {"/api/v1/login/**", "/api/v1/content",};
		// @formatter:off
		http
				// 认证请求
				.authorizeRequests()
				// 放行所有OPTIONS请求
				.antMatchers(HttpMethod.OPTIONS).permitAll()
				// 放行登录方法
				// .antMatchers(antMatchersAnonymous).permitAll()
				// 所有API请求都需要登录访问
				// .antMatchers("/api/**").authenticated()
				.anyRequest().authenticated()
				// RBAC 动态 url 认证
				// .anyRequest().access("@rbacAuthorityService.hasPermission(request,authentication)")
				// 定义错误处理
				// .and().exceptionHandling()
				// 	// 未登录
				// .authenticationEntryPoint(new MyAuthenticationEntryPoint())
				// // 权限不足
				// .accessDeniedHandler(new MyAccessDeniedHandler())
				// 打开Spring Security的跨域
				// .and().cors()
				// // 关闭 CSRF
				// .and().csrf().disable();
				.and().formLogin();

		// 添加自定义的JWT过滤器
    // http.addFilterBefore(new JWTFilter(), LogoutFilter.class);
		// @formatter:on

		return http.build();
	}

	@Bean
	UserDetailsService users() {
		UserDetails user = User.withDefaultPasswordEncoder().username("user").password("password")
				.roles("USER").build();
		return new InMemoryUserDetailsManager(user);
	}

}
