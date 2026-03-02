package com.jwt.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import com.jwt.entity.Users;
import com.jwt.security.JwtService;
import com.jwt.service.CustomeUserDetailsService;

import lombok.extern.slf4j.Slf4j;

import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;


@RestController
@Slf4j
@RequestMapping("/auth")
public class BasicController {

    private final AuthenticationManager authenticationManager;
	
	@Autowired
	private JwtService jwtService;
	
//	@Autowired
//	private CustomeUserDetailsService customeUserDetailsService;

    BasicController(AuthenticationManager authenticationManager) {
        this.authenticationManager = authenticationManager;
    }
	
	@GetMapping("/welcome")
	public String welcome() {
		return "Welcome everyone!!!";
	}
	
	@PostMapping("/login")
	public ResponseEntity<String> login(@RequestBody Users users) {
		try {
			authenticationManager.authenticate(
					new UsernamePasswordAuthenticationToken(users.getUsername(), users.getPassword()));
//			customeUserDetailsService.loadUserByUsername(users.getUsername());
			String token = jwtService.generateToken(users.getUsername());
			return new ResponseEntity<>(token,HttpStatus.OK);
		} catch (Exception e) {
			log.error("Exception occured while generating token..");
			return new ResponseEntity<>("incorrect Username and password",HttpStatus.BAD_REQUEST);
		}
	}
}
