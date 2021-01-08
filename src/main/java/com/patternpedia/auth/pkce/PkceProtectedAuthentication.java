package com.patternpedia.auth.pkce;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.common.exceptions.InvalidGrantException;
import org.springframework.security.oauth2.provider.OAuth2Authentication;

public class PkceProtectedAuthentication {

    Logger logger = LoggerFactory.getLogger(PkceProtectedAuthentication.class);

    private final String codeChallenge;
    private final CodeChallengeMethod codeChallengeMethod;
    private final OAuth2Authentication authentication;

    public PkceProtectedAuthentication(OAuth2Authentication authentication) {
        this.codeChallenge = null;
        this.codeChallengeMethod = CodeChallengeMethod.NONE;
        this.authentication = authentication;
    }

    public PkceProtectedAuthentication(String codeChallenge, CodeChallengeMethod codeChallengeMethod, OAuth2Authentication authentication) {
        this.codeChallenge = codeChallenge;
        this.codeChallengeMethod = codeChallengeMethod;
        this.authentication = authentication;
    }

    public OAuth2Authentication getAuthentication(String codeVerifier) {
        logger.info(codeVerifier);
        logger.info(codeChallenge);
        logger.info(codeChallengeMethod.toString());
        logger.info(codeChallengeMethod.transform(codeVerifier));
        if (codeChallengeMethod == CodeChallengeMethod.NONE) {
            return authentication;
        } else if (codeChallengeMethod.transform(codeVerifier).equals(codeChallenge)) {
            return authentication;
        } else {
            throw new InvalidGrantException("Invalid code verifier.");
        }
    }
}
