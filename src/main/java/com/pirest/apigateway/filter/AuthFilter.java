package com.pirest.apigateway.filter;

import java.util.Map;

import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;

import com.netflix.zuul.ZuulFilter;
import com.netflix.zuul.context.RequestContext;
import com.pirest.apigateway.service.AuthenticationClientService;

@Component
public class AuthFilter extends ZuulFilter {

	private Logger loggger = LoggerFactory.getLogger(this.getClass());

	@Autowired
	private AuthenticationClientService authenticationServiceClient;

	@Override
	public Object run() {
		RequestContext ctx = RequestContext.getCurrentContext();
		HttpServletRequest request = ctx.getRequest();
		String header = request.getHeader("Authorization");
		if (header == null || header.isEmpty()) {
			ctx.setResponseStatusCode(401);
			ctx.setSendZuulResponse(false);
		} else {
			String path = ctx.getRequest().getServletPath();
			if (!path.equalsIgnoreCase("/priest-auth/oauth/token")) {
				String token = header.replace("Bearer ", "");
				loggger.info("Token is '" + header + "'");
				Map<String, Object> responseToken = authenticationServiceClient.validateToken(token);
				if (responseToken == null) {
					ctx.setResponseStatusCode(500);
					ctx.setResponseBody("AuthenticationService Not Available");
					ctx.setSendZuulResponse(false);
				} else {
					loggger.info("Calling service: " + path);
				}
			}
			ctx.addZuulRequestHeader(HttpHeaders.AUTHORIZATION, request.getHeader(HttpHeaders.AUTHORIZATION));
		}
		loggger.info(String.format("%s request to %s", request.getMethod(), request.getRequestURL().toString()));
		return null;
	}

	@Override
	public boolean shouldFilter() {
		return true;
	}

	@Override
	public int filterOrder() {
		return 0;
	}

	@Override
	public String filterType() {
		return "pre";
	}

}
