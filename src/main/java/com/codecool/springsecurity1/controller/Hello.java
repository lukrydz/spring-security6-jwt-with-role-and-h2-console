package com.codecool.springsecurity1.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/")
public class Hello {

    @GetMapping("/hello")
    @PreAuthorize("hasAuthority('USER')")
    public String hello() {
        return "Hello";
    }

}
