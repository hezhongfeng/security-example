package com.example.securityexample.security.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.provisioning.InMemoryUserDetailsManager;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutFilter;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.security.web.savedrequest.HttpSessionRequestCache;


// 一般用户的 security config
@EnableWebSecurity
public class AdminSecurityConfig {

	public static final String ADMIN_SECURITY_CONTEXT_KEY = "ADMIN_SECURITY_CONTEXT";
	public static final String ADMIN_SAVED_REQUEST_KEY = "ADMIN_SECURITY__SAVED_REQUEST";

	public static final String ADMIN_ANT_PATH = "/api/admin/**";

	@Bean
	SecurityFilterChain adminSecurityFilterChain(HttpSecurity http) throws Exception {

		// String[] antMatchersAnonymous = {"/api/v1/login/**", "/api/v1/content",};
		// @formatter:off
		// http
				// 认证请求
				// .authorizeRequests()
				// 放行所有OPTIONS请求
				// .antMatchers(HttpMethod.OPTIONS).permitAll()
				// 放行登录方法
				// .antMatchers(antMatchersAnonymous).permitAll()
				// 所有API请求都需要登录访问
				// .antMatchers("/api/**").authenticated()
				// .anyRequest().authenticated()
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
				// .and().formLogin();

		// 添加自定义的JWT过滤器
    // http.addFilterBefore(new JWTFilter(), LogoutFilter.class);
		// @formatter:on



		// 这里设置的上下文的key和session的key，主要目的是和普通用户区别开来
		HttpSessionSecurityContextRepository securityContextRepository =
				new HttpSessionSecurityContextRepository();
		securityContextRepository.setSpringSecurityContextKey(ADMIN_SECURITY_CONTEXT_KEY);
		HttpSessionRequestCache requestCache = new HttpSessionRequestCache();
		requestCache.setSessionAttrName(ADMIN_SAVED_REQUEST_KEY);

		// @formatter:off

		// 这里需要加上对token的限制
		http.antMatcher(ADMIN_ANT_PATH).csrf().disable()
		    .authorizeRequests().anyRequest().authenticated();

		// @formatter:on

		// http.authorizeRequests(authorizeRequests -> authorizeRequests.anyRequest().authenticated())
		// .formLogin().successHandler(siteAuthenticationSuccessHandler);

		// http.rememberMe();

		return http.build();
	}

	// @Bean
	// UserDetailsService users() {
	// UserDetails user = User.builder().username("user").password(passwordEncoder().encode("1"))
	// .roles("USER").build();
	// return new InMemoryUserDetailsManager(user);
	// }

	// // 密码处理
	// @Bean
	// public PasswordEncoder passwordEncoder() {
	// return new BCryptPasswordEncoder();
	// }

}
