package com.patternpedia.auth.pkce;

import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.common.exceptions.InvalidRequestException;
import org.springframework.security.oauth2.common.util.RandomValueStringGenerator;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.OAuth2Authentication;
import org.springframework.security.oauth2.provider.code.AuthorizationCodeServices;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

@Slf4j
public class PkceAuthorizationCodeServices implements AuthorizationCodeServices {

    private final RandomValueStringGenerator generator = new RandomValueStringGenerator();
    private final Map<String, PkceProtectedAuthentication> authorizationCodeStore = new ConcurrentHashMap<>();

    private final ClientDetailsService clientDetailsService;
    private final PasswordEncoder passwordEncoder;

    public PkceAuthorizationCodeServices(ClientDetailsService clientDetailsService, PasswordEncoder passwordEncoder) {
        this.clientDetailsService = clientDetailsService;
        this.passwordEncoder = passwordEncoder;
    }

    @Override
    public String createAuthorizationCode(OAuth2Authentication authentication) {
        PkceProtectedAuthentication protectedAuthentication = getProtectedAuthentication(authentication);
        String code = generator.generate();
        authorizationCodeStore.put(code, protectedAuthentication);
        return code;
    }

    private PkceProtectedAuthentication getProtectedAuthentication(OAuth2Authentication authentication) {
        Map<String, String> requestParameters = authentication.getOAuth2Request().getRequestParameters();

        if (isPublicClient(requestParameters.get("client_id")) && !requestParameters.containsKey("code_challenge")) {
            throw new InvalidRequestException("Code challenge required.");
        }

        if (requestParameters.containsKey("code_challenge")) {
            String codeChallenge = requestParameters.get("code_challenge");
            CodeChallengeMethod codeChallengeMethod = getCodeChallengeMethod(requestParameters);
            return new PkceProtectedAuthentication(codeChallenge, codeChallengeMethod, authentication);
        }

        return new PkceProtectedAuthentication(authentication);
    }

    private CodeChallengeMethod getCodeChallengeMethod(Map<String, String> requestParameters) {
        try {
            return Optional.ofNullable(requestParameters.get("code_challenge_method"))
                    .map(String::toUpperCase)
                    .map(CodeChallengeMethod::valueOf)
                    .orElse(CodeChallengeMethod.PLAIN);
        } catch (IllegalArgumentException e) {
            throw new InvalidRequestException("Transform algorithm not supported");
        }
    }

    private boolean isPublicClient(String clientId) {
        if (clientId.equals("pattern-pedia-public")) {
            return false;
        }
        String clientSecret = clientDetailsService.loadClientByClientId(clientId).getClientSecret();

        return clientSecret == null || passwordEncoder.matches("", clientSecret);
    }

    @Override
    public OAuth2Authentication consumeAuthorizationCode(String code) {
        throw new UnsupportedOperationException();
    }

    public OAuth2Authentication consumeAuthorizationCodeAndCodeVerifier(String code, String verifier) {
        return authorizationCodeStore.get(code).getAuthentication(verifier);
    }
}
