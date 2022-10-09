package com.example.securityexample.security.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Bean;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

// 这个类只要实现了就可以，不需要在security里面进行配置
@Service
public class UserDetailsServiceImpl implements UserDetailsService {

  private static final String USERNAME = "user";
  private static final String PASSWORD = "1";

  @Override
  public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
    // TODO Auto-generated method stub
    // return null;
    // SysUserEntity sysUserEntity = sysUserRepository.findByUsername(username);
    // Set<SysRoleEntity> roleSet = sysUserEntity.getRoles();
    // Set<SimpleGrantedAuthority> authorities =
    // roleSet.stream().flatMap(role->role.getMenus().stream())
    // .filter(menu-> StringUtils.isNotBlank(menu.getCode()))
    // .map(SysMenuEntity::getCode)
    // .map(SimpleGrantedAuthority::new)
    // .collect(Collectors.toSet());
    // // return new User(sysUserEntity.getUsername(), sysUserEntity.getPassword(), authorities);
    // return new MyUserDetails(sysUserEntity.getUsername(), sysUserEntity.getPassword(),
    // 1==sysUserEntity.getEnabled(), authorities);



    if (!USERNAME.equals(username)) {
      throw new UsernameNotFoundException("用户名不存在");
    }

    // UserDetails user = User.builder().username(USERNAME)
    // .password(new BCryptPasswordEncoder().encode(PASSWORD)).roles("USER").build();

    // return (UserDetails) new InMemoryUserDetailsManager(user);

    UserDetails userDetails = new User(USERNAME, new BCryptPasswordEncoder().encode(PASSWORD),
        AuthorityUtils.commaSeparatedStringToAuthorityList("admin,common"));

    return userDetails;
  }

}
