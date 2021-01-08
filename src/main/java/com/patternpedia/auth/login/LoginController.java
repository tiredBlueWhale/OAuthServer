package com.patternpedia.auth.login;

import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseCookie;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

import java.time.LocalDateTime;
@Slf4j
@Controller
class LoginController {

    @GetMapping("/login")
    String login() {
        return "login";
    }

    @GetMapping("/signup")
    String signup() {
        return "signup";
    }

}