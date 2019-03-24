import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.algorithms.Algorithm;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class TestApp1 {

    private String createJwt() {
        JWTCreator.Builder builder = JWT.create();
        Map<String, Object> headerMaps = new HashMap<>();
        //headerMaps.put("alg", "none");
        //builder.withHeader(headerMaps);
        builder.withIssuer("issuerExample2");
        builder.withExpiresAt(Date.from(Instant.now()));
        builder.withClaim("http://example.com/is_root", "true");
        String jwt = builder.sign(Algorithm.none());
        System.out.println(jwt);
        String jwt2 = JWT.create().
                withClaim("abc", "jyoti").
                withClaim("xyz", "Sharma").sign(Algorithm.none());
        System.out.printf("jwt2---------" + jwt2);
        return jwt;

    }

    public static void main(String[] args) {
        TestApp1 testApp = new TestApp1();
        testApp.createJwt();
    }
}
