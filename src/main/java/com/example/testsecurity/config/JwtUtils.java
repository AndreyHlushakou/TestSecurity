package com.example.testsecurity.config;

import com.example.testsecurity.exceprion.NotFoundCorrectSecretException;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.io.DecodingException;
import io.jsonwebtoken.security.InvalidKeyException;
import io.jsonwebtoken.security.Keys;
import io.jsonwebtoken.security.WeakKeyException;
import jakarta.annotation.PostConstruct;
import lombok.AccessLevel;
import lombok.NoArgsConstructor;
import lombok.experimental.FieldDefaults;
import lombok.experimental.NonFinal;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.time.Instant;
import java.time.ZonedDateTime;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

@Slf4j
@Component
@NoArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE, makeFinal = true)
public class JwtUtils {

    @NonFinal
    @Value("${security.jwt.access-secret-key}")
    String accessSecretKey;
    @NonFinal
    @Value("${security.jwt.access-token-lifetime}")
    long accessTokenLifeTime;
    @NonFinal
    @Value("${security.jwt.access-unit}")
    ChronoUnit accessUnit;

    @NonFinal
    @Value("${security.jwt.refresh-secret-key}")
    String refreshSecretKey;
    @NonFinal
    @Value("${security.jwt.refresh-token-lifetime}")
    long refreshTokenLifeTime;
    @NonFinal
    @Value("${security.jwt.refresh-unit}")
    ChronoUnit refreshUnit;

    static Map<SecretEnum, TripletSecret> SECRETS_MAP = new HashMap<>(SecretEnum.values().length);

    public record TripletSecret(SecretKey secretKey,
                                Long lifeTime,
                                ChronoUnit chronoUnit) {}

    public enum SecretEnum {
        ACCESS_SECRET,
        REFRESH_SECRET,
    }

    @PostConstruct
    public void initSecretsMap() {
        TripletSecret tripletSecretAccess = new TripletSecret(getSigningKey(
                accessSecretKey),
                accessTokenLifeTime,
                accessUnit);
        TripletSecret tripletSecretRefresh = new TripletSecret(getSigningKey(
                refreshSecretKey),
                refreshTokenLifeTime,
                refreshUnit);
        SECRETS_MAP.put(SecretEnum.ACCESS_SECRET, tripletSecretAccess);
        SECRETS_MAP.put(SecretEnum.REFRESH_SECRET, tripletSecretRefresh);
    }

    private static SecretKey getSigningKey(String secretKey) throws DecodingException, WeakKeyException {
        byte[] keyBytes = Decoders.BASE64.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    //generate
    public static String generateToken(Authentication authentication, SecretEnum secretEnum) throws InvalidKeyException {
        TripletSecret tripletSecret = SECRETS_MAP.get(secretEnum);
        long lifeTime = tripletSecret.lifeTime;
        ChronoUnit chronoUnit = tripletSecret.chronoUnit;
        SecretKey secretKey = tripletSecret.secretKey;

        UserDetails userDetails= (UserDetails) authentication.getPrincipal();

        ZonedDateTime now = ZonedDateTime.now();
        Instant instant = now.plus(lifeTime, chronoUnit).toInstant();
        Date dateNow = Date.from(now.toInstant());
        Date dateTo = Date.from(instant);

        return Jwts.builder()
                //header
                .header()
                .type("JWT")
                //payload
                .and()
                .subject(userDetails.getUsername())
                .issuedAt(dateNow)
                .expiration(dateTo)
                //signature
                .signWith(secretKey)
                .compact();
    }

    //check
    public static Map.Entry<SecretEnum, TripletSecret> getSecretEnum(String token) throws NotFoundCorrectSecretException {
        for (Map.Entry<SecretEnum, TripletSecret> secretEnumPairEntry : SECRETS_MAP.entrySet()) {
            SecretKey secretKey = secretEnumPairEntry.getValue().secretKey;
            try {
                extractPayload(secretKey, token);
            } catch (JwtException | IllegalArgumentException ex) {
                log.debug("JwtUtils: getSecretEnum. {}", ex.getMessage());
                continue;
            }
            return secretEnumPairEntry;
        }
        throw new NotFoundCorrectSecretException();
    }

    public static boolean isTokenCorrectType(String token, SecretEnum secretEnum) {
        SecretKey secretKey = SECRETS_MAP.get(secretEnum).secretKey;
        try {
            extractPayload(secretKey, token);
        } catch (JwtException | IllegalArgumentException ex) {
            log.debug("JwtUtils: Incorrect type token");
            return false;
        }
        return true;
    }

    public static boolean isTokenValid(String token, UserDetails userDetails) {
        String username = extractUserName(token);
        Date date = extractExpiration(token);
        if (username != null && date != null) {
            boolean bool1 = username.equals(userDetails.getUsername());
            boolean bool2 = !date.before(new Date());
            return bool1 && bool2;
        }
        return false;
    }

    public static String extractUserName(String token) {
        return extractClaim(Claims::getSubject, token);
    }

    public static String extractUserName(String token, SecretEnum secretEnum) {
        SecretKey secretKey = SECRETS_MAP.get(secretEnum).secretKey;
        return extractClaim(Claims::getSubject, token, secretKey);
    }

    public static Date extractExpiration(String token) {
        return extractClaim(Claims::getExpiration, token);
    }

    public static Date extractExpiration(String token, SecretEnum secretEnum) {
        SecretKey secretKey = SECRETS_MAP.get(secretEnum).secretKey;
        return extractClaim(Claims::getExpiration, token, secretKey);
    }

    private static <T> T extractClaim(Function<Claims, T> claimsResolver, String token) {
        try {
            SecretKey secretKey = getSecretEnum(token).getValue().secretKey;
            return extractClaim(claimsResolver, token, secretKey);
        } catch (NotFoundCorrectSecretException ex) {
            log.debug("JwtUtils: extractClaims. {}", ex.getMessage());
        }
        return null;
    }

    private static <T> T extractClaim(Function<Claims, T> claimsResolver, String token, SecretKey secretKey) {
        try {
            return claimsResolver.apply(extractPayload(secretKey, token));
        } catch (JwtException | IllegalArgumentException ex) {
            log.debug("JwtUtils: extractClaims. {}", ex.getMessage());
        }
        return null;
    }

    private static Claims extractPayload(SecretKey secretKey, String token) throws JwtException, IllegalArgumentException {
        return Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

}
