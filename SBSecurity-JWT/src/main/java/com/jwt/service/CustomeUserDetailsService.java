package com.jwt.service;

import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.User;

import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

import com.jwt.entity.Users;
import com.jwt.repo.UserRepository;

@Service
public class CustomeUserDetailsService implements UserDetailsService{
	
	@Autowired
	UserRepository repository;

	@Override
	public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
		
		Optional<Users> byUsername = repository.findByUsername(username);
		
		if(byUsername.isPresent()) {
			Users users = byUsername.get();
			return User
					.withUsername(users.getUsername())
					.password(users.getPassword())
					.roles(users.getRole())
					.build();
		}
		
		throw new UsernameNotFoundException(username+" User not found!!");
	}

}
