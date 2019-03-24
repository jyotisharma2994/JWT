import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator;
import com.auth0.jwt.algorithms.Algorithm;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.*;
import java.time.Instant;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;

public class TestApp {

    public static SecretKey generateKey() throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(256); // 128 default; 192 and 256 also possible
        return keyGenerator.generateKey();
    }

//    SecureRandom secureRandom = new SecureRandom();
//    byte[] key = new byte[16];
//    secureRandom.nextBytes(key);
//    SecretKey secretKey = SecretKeySpec(key, "AES");

    //encrypting the contentKeyGen

//    String encodedString = Base64.getEncoder().encodeToString(generateKey().getBytes());


    byte[] iv = new byte[12]; //NEVER REUSE THIS IV WITH SAME KEY

    /*private String createJws() {
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
    }*/

/*
    The following example JWE Header declares that:

    the Content Encryption Key is encrypted to the recipient using the RSA-PKCS1_1.5 algorithm to produce the JWE Encrypted Key,
    the Plaintext is encrypted using the AES-256-GCM algorithm to produce the JWE Ciphertext,
    the specified 64-bit Initialization Vector with the base64url encoding __79_Pv6-fg was used, and
    the thumbprint of the X.509 certificate that corresponds to the key used to encrypt the JWE has the base64url encoding 7noOPq-hJ1_hCnvWh6IeYI2w9Q0.

    {"alg":"RSA1_5",
 "enc":"A256GCM",
 "iv":"__79_Pv6-fg",
 "x5t":"7noOPq-hJ1_hCnvWh6IeYI2w9Q0"}

*/

    private String createJwe() {
        JWTCreator.Builder builder = JWT.create();
        Map<String, Object> headerMaps = new HashMap<>();
        headerMaps.put("alg", "RSA1_5");
        headerMaps.put("enc", "A256GCM");
        headerMaps.put("iv", "__79_Pv6");
        headerMaps.put("x5t", "7noOPq-hJ1_hCnvWh6IeYI2w9Q0");
        builder.withHeader(headerMaps);
        builder.withIssuer("issuerAgency");
        builder.withIssuedAt(Date.from(Instant.now()));
        builder.withClaim("http://example.com/is_root", "true");
        builder.sign(Algorithm.)

    }
/*

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
*/

    public static void main(String[] args) {
        TestApp testApp = new TestApp();
        testApp.createJwe();

        KeyPair generateKeyPair = generateKeyPair();

        KeyPairGenerator keyGen = KeyPairGenerator.getInstance(ALGORITHM);

        SecureRandom random = SecureRandom.getInstance("SHA1PRNG", "SUN");

        // 512 is keysize
        keyGen.initialize(512, random);

        KeyPair generateKeyPair = keyGen.generateKeyPair();
        byte[] publicKey = generateKeyPair.getPublic().getEncoded();
        byte[] privateKey = generateKeyPair.getPrivate().getEncoded();

        PublicKey key = KeyFactory.getInstance(ALGORITHM)
                .generatePublic(new X509EncodedKeySpec(publicKey));

        Cipher cipher = Cipher.getInstance(ALGORITHM);
        cipher.init(Cipher.ENCRYPT_MODE, key);

        byte[] encryptedBytes = cipher.doFinal("".getBytes());
    }
}
