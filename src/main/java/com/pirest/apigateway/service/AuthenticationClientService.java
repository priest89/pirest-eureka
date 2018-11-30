package com.pirest.apigateway.service;

import java.util.Map;

import org.springframework.cloud.openfeign.FeignClient;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

@FeignClient(name = "priest-auth")
public interface AuthenticationClientService {

	@GetMapping("/oauth/check_token")
	public Map<String, Object> validateToken(@RequestParam("token") String token);
}
