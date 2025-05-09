package com.example.testsecurity.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.JwtBuilder;
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
@NoArgsConstructor(access = AccessLevel.PRIVATE)
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

    static String DEFAULT_SECRET_KEY = "26947ebfd2f35047c2aa750bfc9ec4a0c5bd84b2076d29258e4100416560210c";
    static long DEFAULT_TOKEN_LIFE_TIME = 1L;
    static ChronoUnit DEFAULT_UNIT = ChronoUnit.DAYS;

    static Map<SecretEnum, TripletSecret> SECRETS_MAP = new HashMap<>(SecretEnum.values().length);

    public record TripletSecret(SecretKey secretKey,
                                Long lifeTime,
                                ChronoUnit chronoUnit) {}

    public enum SecretEnum {
        ACCESS_SECRET,
        REFRESH_SECRET,
        DEFAULT_SECRET
    }

    @PostConstruct
    public void initStatic() {
        TripletSecret tripletSecretAccess = new TripletSecret(getSigningKey(
                accessSecretKey),
                accessTokenLifeTime,
                accessUnit);
        TripletSecret tripletSecretRefresh = new TripletSecret(getSigningKey(
                refreshSecretKey),
                refreshTokenLifeTime,
                refreshUnit);
        TripletSecret tripletSecretDefault = new TripletSecret(
                getSigningKey(DEFAULT_SECRET_KEY),
                DEFAULT_TOKEN_LIFE_TIME,
                DEFAULT_UNIT);
        SECRETS_MAP.put(SecretEnum.ACCESS_SECRET, tripletSecretAccess);
        SECRETS_MAP.put(SecretEnum.REFRESH_SECRET, tripletSecretRefresh);
        SECRETS_MAP.put(SecretEnum.DEFAULT_SECRET, tripletSecretDefault);
    }

    private static SecretKey getSigningKey(String secretKey) throws DecodingException, WeakKeyException {
        byte[] keyBytes = Decoders.BASE64URL.decode(secretKey);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    //generate
    public static String generateToken(Authentication authentication, SecretEnum secretEnum) {
        long lifeTime = SECRETS_MAP.get(secretEnum).lifeTime;
        ChronoUnit chronoUnit = SECRETS_MAP.get(secretEnum).chronoUnit;
        SecretKey secretKey = SECRETS_MAP.get(secretEnum).secretKey;

        UserDetails userDetails= (UserDetails) authentication.getPrincipal();

        ZonedDateTime now = ZonedDateTime.now();
        Instant instant = now.plus(lifeTime, chronoUnit).toInstant();
        Date dateNow = Date.from(now.toInstant());
        Date dateTo = Date.from(instant);

        JwtBuilder builder = Jwts.builder()
                .header().type("JWT").and()
                .subject(userDetails.getUsername())
                .issuedAt(dateNow)
                .expiration(dateTo)
                ;
        try {
            return builder.signWith(secretKey)
                    .compact();
        } catch (InvalidKeyException e) {
            log.error("CREATE NEW ACCESS AND REFRESH SECRETS!!!\nIncorrect secretKey.\nWill be used: DEFAULT_SECRET_KEY.\n");
            return builder.signWith(SECRETS_MAP.get(SecretEnum.DEFAULT_SECRET).secretKey)
                    .compact();
        }
    }

    //check
    public static Map.Entry<SecretEnum, TripletSecret> getSecretEnum(String token) throws RuntimeException{
        for (Map.Entry<SecretEnum, TripletSecret> secretEnumPairEntry : SECRETS_MAP.entrySet()) {
            SecretKey secretKey = secretEnumPairEntry.getValue().secretKey;
            try {
                extractPayload(secretKey, token);
            } catch (Exception ignored) {
                continue;
            }
            return secretEnumPairEntry;
        }
        throw new RuntimeException("Not found correct secret");
    }

    public static boolean isTokenCorrectType(String token, SecretEnum secretEnum) {
        try {
            SecretEnum secretEnumByToken = getSecretEnum(token).getKey();
            if (!(secretEnumByToken == secretEnum || secretEnumByToken == SecretEnum.DEFAULT_SECRET)) {
                log.warn("Incorrect type token");
                return false;
            }
            return true;
        } catch (RuntimeException e) {
            log.error("Incorrect token");
        }
        return false;
    }

    public static boolean isTokenValid(String token, UserDetails userDetails) {
        try {
            getSecretEnum(token);
            String username = extractUserName(token);
            boolean bool1 = username.equals(userDetails.getUsername());
            Date date = extractExpiration(token);
            boolean bool2 = !date.before(new Date());
            return bool1 && bool2;
        } catch (RuntimeException ignored) {
            return false;
        }
    }

    public static String extractUserName(String token) {
        return extractClaim(Claims::getSubject, token);
    }

    public static Date extractExpiration(String token) {
        return extractClaim(Claims::getExpiration, token);
    }

    private static <T> T extractClaim(Function<Claims, T> claimsResolver, String token) throws JwtException, IllegalArgumentException {
        SecretKey secretKey = getSecretEnum(token).getValue().secretKey;
        return claimsResolver.apply(extractPayload(secretKey, token));
    }

    private static Claims extractPayload(SecretKey secretKey, String token) throws JwtException, IllegalArgumentException {
        return Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token)
                .getPayload();
    }

}
