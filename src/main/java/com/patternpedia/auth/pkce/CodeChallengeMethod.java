package com.patternpedia.auth.pkce;

import org.bouncycastle.util.encoders.Hex;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Base64;

public enum CodeChallengeMethod {

    S256 {
        @Override
        public String transform(String codeVerifier) {
            try {
//                MessageDigest digest = MessageDigest.getInstance("SHA-256");
//                byte[] hash = digest.digest(codeVerifier.getBytes(StandardCharsets.UTF_8));
//                return Base64.getUrlEncoder().encodeToString(Hex.encode(hash));
                byte[] bytes = codeVerifier.getBytes(StandardCharsets.US_ASCII);
                MessageDigest messageDigest = MessageDigest.getInstance("SHA-256");
                messageDigest.update(bytes, 0, bytes.length);
                byte[] digest = messageDigest.digest();
                return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
            } catch (NoSuchAlgorithmException e) {
                throw new IllegalStateException(e);
            }
        }
    },
    PLAIN {
        @Override
        public String transform(String codeVerifier) {
            return codeVerifier;
        }
    },
    NONE {
        @Override
        public String transform(String codeVerifier) {
            throw new UnsupportedOperationException();
        }
    };


    public abstract String transform(String codeVerifier);
}