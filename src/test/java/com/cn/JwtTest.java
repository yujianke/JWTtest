package com.cn;

import com.alibaba.fastjson.JSON;
import io.jsonwebtoken.*;
import org.junit.Test;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.jwt.Jwt;
import org.springframework.security.jwt.JwtHelper;
import org.springframework.security.jwt.crypto.sign.RsaSigner;
import org.springframework.security.jwt.crypto.sign.RsaVerifier;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

import java.io.UnsupportedEncodingException;
import java.security.KeyPair;
import java.security.interfaces.RSAPrivateKey;
import java.util.Base64;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

public class JwtTest {
    /**对称加密HS256*/
    @Test
    public void createJwt(){
        long l = System.currentTimeMillis();
        JwtBuilder builder = Jwts.builder();
        builder.setId("abcd")
                .setIssuer("iss")
                .setExpiration(new Date(l+2000))//设置过期时间
                .signWith(SignatureAlgorithm.HS256,"yujianke");//设置签名;
        Map<String, Object> map = new HashMap<>();
        map.put("address","beijing");
        builder.addClaims(map);
        String compact = builder.compact();
        System.out.println("生成的JWT为:"+compact);

    }


    @Test
    public void parseJwt(){
        JwtParser jwtParser = Jwts.parser().setSigningKey("yujianke");
        Jws<Claims> claimsJws = jwtParser.parseClaimsJws("eyJhbGciOiJIUzI1NiJ9.eyJqdGkiOiJhYmNkIiwiaXNzIjoiaXNzIiwiZXhwIjoxNjI0MDI0NTMxLCJhZGRyZXNzIjoiYmVpamluZyJ9.nAL7P6oDzDpgiIv2Z1uuuTdBKuW_q0XGpIBKyeqhTjg");
        Claims body = claimsJws.getBody();
        System.out.println("解析JWT为:"+body);
    }
    @Test
    public void testBase64() throws UnsupportedEncodingException {
        byte[] encode = Base64.getDecoder()
                .decode("eyJhbGciOiJIUzI1NiJ9".getBytes("UTF-8"));
        byte[] encode1 = Base64.getDecoder()
                .decode("eyJqdGkiOiJhYmNkIiwiaXNzIjoiaXNzIiwiZXhwIjoxNjI0MDI0NTMxLCJhZGRyZXNzIjoiYmVpamluZyJ9".getBytes("UTF-8"));
        System.out.println(new String(encode,"UTF-8"));
        System.out.println(new String(encode1,"UTF-8"));
    }


   /**非对称加密RS256 公钥私钥*/
   @Test
   public void testCtestJwt(){
       //证书文件路径
       String key_location="changgou.jks";
       //秘钥库密码
       String key_password="changgou";
       //秘钥密码
       String keypwd = "changgou";
       //秘钥别名
       String alias = "changgou";
       ClassPathResource resource = new ClassPathResource(key_location);
       //创建秘钥工厂
       KeyStoreKeyFactory keyStoreKeyFactory = new KeyStoreKeyFactory(resource, key_password.toCharArray());
       //读取秘钥对(公钥、私钥)
       KeyPair keyPair = keyStoreKeyFactory.getKeyPair(alias, keypwd.toCharArray());
       //获取私钥
       RSAPrivateKey aPrivate = (RSAPrivateKey) keyPair.getPrivate();

       //自定义Payload
       Map<String, Object> tokenMap = new HashMap<>();
       tokenMap.put("id", "1");
       tokenMap.put("name", "itheima");
       tokenMap.put("roles", "ROLE_VIP,ROLE_USER");

       Jwt jwt = JwtHelper.encode(JSON.toJSONString(tokenMap), new RsaSigner(aPrivate));
       String encoded = jwt.getEncoded();
       System.out.println("通过私钥生成jwt:"+encoded);


   }

    @Test
    public void testparsetestJwt(){
        //令牌
        String token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJyb2xlcyI6IlJPTEVfVklQLFJPTEVfVVNFUiIsIm5hbWUiOiJpdGhlaW1hIiwiaWQiOiIxIn0.LfpsJg4J8eLiVMhZ9gbF_9sa17MBM8jHCpQSu4FeZ_8MeQto3CsgBrJc5zkIJDzMpNlK--m0bMMS6DwnEv804l1s_4cb7jghWI9yy6yx8B6hpHnkffeYV4joumbM_KJM0bpe7nnfRE6wjAvaogz78ezsZd_qz6KakIKYPM6eyl2_z6bspxf2S_-03mzO4Pv4mWQJt2S4y6EMVXjBx4SAYa7KQ-uNZIX-QDKtFGBaSmk5WuVO_5VLUNGJmY4-M0W40Gc3XkLgy6TLboefeS7rRJJpqkqt-X1w1tSim1tZ0wEXQz80BTBcN6XTVoqzDoVIpn8UeWBbPHfBpDe8tkJ3kA";

        //公钥
        String publickey = "-----BEGIN PUBLIC KEY----- MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAhwqIBhc9iA5IcSu1SVujWJDGCW7AfA2AvarffDjRE6TXMjwV4/3O+WEwO8CgsyVtZ4UmE3M3VF1XDOUaE/kydSVPMv2VC4NQJv6TdAQhaw+utREYCmn7rdsdY716l+Z1ZCRKzy8DrQ/SLIPEh2MK fPp+Bf9+PRedKdKuh5NTVW+e30HO1fq/DjURDWVGs2FYgz5mHt0p1GVINHfIKUzx qXhpqW6WyDcTSKaabIot38EcCP12PHxvhGZ2qZkPt2cMabrhBNPl9bAtTYZEjkEl GgrkE8mHhdQQtRyZverbxflSpVJzrP/54nNsrI36rEAexfPlNuiu63VfoydMMOn+ fwIDAQAB-----END PUBLIC KEY-----";

        //校验Jwt
        Jwt jwt = JwtHelper.decodeAndVerify(token, new RsaVerifier(publickey));

        //获取Jwt原始内容 载荷
        String claims = jwt.getClaims();
        System.out.println(claims);
        //jwt令牌
        String encoded = jwt.getEncoded();
        System.out.println(encoded);

    }


}
