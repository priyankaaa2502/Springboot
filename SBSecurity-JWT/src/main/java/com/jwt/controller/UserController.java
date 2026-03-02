package com.jwt.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/user")
public class UserController {

	@PreAuthorize("hasRole('USER')")
    @GetMapping("/profile")
    public String profile() {
        return "User Profile Data";
    }

    @PreAuthorize("hasAnyRole('USER','ADMIN')")
    @GetMapping("/common")
    public String commonAccess() {
        return "Accessible by both User and Admin";
    }
}