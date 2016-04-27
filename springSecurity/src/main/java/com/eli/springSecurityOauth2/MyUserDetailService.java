package com.eli.springSecurityOauth2;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import javax.management.relation.Role;

import org.apache.commons.lang3.StringUtils;
import org.springframework.security.core.*;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

public class MyUserDetailService implements UserDetailsService
{
	//登陆验证时，通过username获取用户的所有权限信息，
	//并返回User放到spring的全局缓存SecurityContextHolder中，以供授权器使用
    public UserDetails loadUserByUsername(String userName) throws UsernameNotFoundException
    {
    	
    	List<GrantedAuthority> auths = null;
    	SimpleGrantedAuthority role_admin = new SimpleGrantedAuthority("ROLE_ADMIN");
    	SimpleGrantedAuthority role_user = new SimpleGrantedAuthority("ROLE_USER");
    	
    	if(StringUtils.equals(userName, "lcy"))
    	{
    		auths = new ArrayList<GrantedAuthority>();
    		auths.add(role_admin);
    		auths.add(role_user);    		
    	}
    	
    	User user = new User(userName, "lcy", true, true, true, true, auths);
		return user;
    	
	}
	

}
