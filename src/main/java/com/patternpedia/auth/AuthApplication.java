package com.patternpedia.auth;

import com.patternpedia.auth.user.CreateUserController;
import com.vladmihalcea.hibernate.type.util.Configuration;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class AuthApplication {

	public static void main(String[] args) {
		System.setProperty(Configuration.PropertyKey.PRINT_BANNER.getKey(), Boolean.FALSE.toString());
		SpringApplication.run(AuthApplication.class, args);
	}
}
