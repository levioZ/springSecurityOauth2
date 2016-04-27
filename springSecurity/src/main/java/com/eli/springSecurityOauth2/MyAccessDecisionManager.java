package com.eli.springSecurityOauth2;

import java.util.Collection;
import java.util.Iterator;

import org.apache.commons.lang3.StringUtils;
import org.springframework.security.access.AccessDecisionManager;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.ConfigAttribute;
import org.springframework.security.access.SecurityConfig;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.util.CollectionUtils;

public class MyAccessDecisionManager implements AccessDecisionManager 
{
	//检查用户是否够权限访问资源
	//参数authentication是从spring的全局缓存SecurityContextHolder中拿到的，里面是用户的权限信息
	//参数object是url
	//参数configAttributes所需的权限
	@Override
	public void decide(Authentication authentication, Object obj, Collection<ConfigAttribute> configAttributes)
			throws AccessDeniedException, InsufficientAuthenticationException 
	{  
		if(CollectionUtils.isEmpty(configAttributes))
		{
			return;
		}
		
		Iterator<ConfigAttribute> iterator = configAttributes.iterator();
		while (iterator.hasNext()) 
		{
			SecurityConfig securityConfig = (SecurityConfig)iterator.next();
			String role =  securityConfig.getAttribute();
			for(GrantedAuthority gAuthority: authentication.getAuthorities())
			{
				if(StringUtils.equals(role, gAuthority.getAuthority()))
				{
					return;
				}
			}
			
		}
		
		//注意：执行这里，后台是会抛异常的，但是界面会跳转到所配的access-denied-page页面
				throw new AccessDeniedException("no right");   
		
 		
	}

	@Override
	public boolean supports(Class<?> class1)
	{
		return true;
	}

	@Override
	public boolean supports(ConfigAttribute configattribute) 
	{
		return true;
	}
	
   
}
