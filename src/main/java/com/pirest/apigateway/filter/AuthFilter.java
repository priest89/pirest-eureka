package com.pirest.apigateway.filter;

import javax.servlet.http.HttpServletRequest;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
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
	    if (header == null || header.isEmpty() || !header.startsWith("Bearer ")) {
	        ctx.setResponseStatusCode(401);
	        ctx.setSendZuulResponse(false);
	    } else {
	        header = header.replace("Bearer ", "");
	        loggger.info("Token is '" + header + "'");
	        ResponseEntity<String> responseToken = authenticationServiceClient.validateToken(header);

	        if (responseToken == null) {
	            ctx.setResponseStatusCode(500);
	            ctx.setResponseBody("AuthenticationService Not Available");
	            ctx.setSendZuulResponse(false);
	        } else {
	            loggger.info(responseToken.getStatusCode().name());
	            loggger.info(responseToken.getBody().toString());
	        }
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
