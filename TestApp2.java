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

public class TestApp2 {

    private String createJws() {
        JWTCreator.Builder builder = JWT.create();
        Map<String, Object> headerMaps = new HashMap<>();
        headerMaps.put("typ", "JWT");
        headerMaps.put("alg", "HS256");
        builder.withHeader(headerMaps);
        builder.withIssuer("issuerExample");
        builder.withExpiresAt(Date.from(Instant.now()));
        builder.withClaim("http://example.com/is_root", "true");
        String jwt = builder.sign(Algorithm.HMAC256("abc")); //abc is the secret required to for one way hash
        System.out.println(jwt);
        return jwt;
    }
    public static void main(String[] args) {
        TestApp2 testApp = new TestApp2();
        testApp.createJws();
    }
}
