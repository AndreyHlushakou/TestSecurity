package com.example.testsecurity.config;

import com.example.testsecurity.entity.UserEntity;
import com.example.testsecurity.exceprion.NotFoundCorrectSecretException;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.function.Executable;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;

import static org.junit.jupiter.api.Assertions.assertThrows;

@SpringBootTest(classes = JwtUtils.class)
public class JwtUtilsTest {

    @Test
    public void getSecretEnumTest() {
        UserEntity user = new UserEntity();
        user.setUsername("user");
        user.setPassword("user");
        Authentication authenticationTest = UsernamePasswordAuthenticationToken.unauthenticated(user, null);
        String token =  JwtUtils.generateToken(authenticationTest, JwtUtils.SecretEnum.ACCESS_SECRET) + "aaa";

        Executable executable = () -> JwtUtils.getSecretEnum(token);
        assertThrows(NotFoundCorrectSecretException.class, executable, "Not found correct secret");
    }
}
