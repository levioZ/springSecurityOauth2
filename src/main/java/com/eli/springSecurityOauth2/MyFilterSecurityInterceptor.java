
package com.eli.springSecurityOauth2;

import java.io.IOException;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;

import org.springframework.security.access.SecurityMetadataSource;
import org.springframework.security.access.intercept.AbstractSecurityInterceptor;
import org.springframework.security.access.intercept.InterceptorStatusToken;
import org.springframework.security.web.FilterInvocation;
import org.springframework.security.web.access.intercept.FilterInvocationSecurityMetadataSource;

public class MyFilterSecurityInterceptor extends AbstractSecurityInterceptor implements Filter 
{
	//从配置文件注入
	private FilterInvocationSecurityMetadataSource securityMetadataSource;

	public void destroy()
	{
		
	}
    
	//登陆后，每次访问资源都通过这个拦截器拦截
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException,ServletException
	{
		FilterInvocation fInvocation = new FilterInvocation(request, response, chain);
		invoke(fInvocation);
	}
	
	public void invoke(FilterInvocation fInvocation) throws IOException, ServletException
	{
		//fInvocation里面有一个被拦截的url
		//里面调用MyInvocationSecurityMetadataSource的getAttributes(Object object)这个方法获取fInvocation对应的所有权限
		//再调用MyAccessDecisionManager的decide方法来校验用户的权限是否足够
		InterceptorStatusToken token = super.beforeInvocation(fInvocation);
		try {
			//执行下一个拦截器
			fInvocation.getChain().doFilter(fInvocation.getRequest(), fInvocation.getResponse());   
			} 
		finally { 
				super.afterInvocation(token, null);  
			}   
	}  
	
    
	

	public void init(FilterConfig arg0) throws ServletException
	{
		
	}

	public Class<? extends Object> getSecureObjectClass()
	{
	   return FilterInvocation.class;
	}

	public SecurityMetadataSource obtainSecurityMetadataSource()
	{
	  return this.securityMetadataSource;
	}

	public FilterInvocationSecurityMetadataSource getSecurityMetadataSource() {
		return securityMetadataSource;
	}

	public void setSecurityMetadataSource(FilterInvocationSecurityMetadataSource securityMetadataSource) {
		this.securityMetadataSource = securityMetadataSource;
	}
	
	
	

}
