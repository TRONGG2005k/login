package com.example.test_user.service;


import com.example.test_user.dto.LoginRequestDto;
import com.example.test_user.dto.LogoutRequestDto;
import com.example.test_user.entity.InvalidatedToken;
import com.example.test_user.entity.User;
import com.example.test_user.repository.InvalidatedTokenRepository;
import com.example.test_user.repository.UserRepository;
import com.example.test_user.response.LoginResponse;
import com.example.test_user.response.UserResponse;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.util.WebUtils;

import java.text.ParseException;
import java.util.Date;
import java.util.UUID;

@Slf4j
@Service
public class AuthenticationService {
    @Autowired
    private UserRepository userRepository;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private InvalidatedTokenRepository invalidatedTokenRepository;

    @Value("${jwt.signerKey}")
    protected String SECRET_KEY;

    private static final long ACCESS_TOKEN_EXPIRATION = 15 * 60 * 1000; // 15 phút
    private static final long REFRESH_TOKEN_EXPIRATION = 7 * 24 * 60 * 60 * 1000;

    /*
    * cấu hình login
    * */


    public LoginResponse<UserResponse> login(LoginRequestDto request, HttpServletResponse response) {
        System.out.println("Username từ request: " + request.getUserName());
        var user = userRepository.findByUserName(request.getUserName())
                .orElseThrow(() -> new RuntimeException("user not existed"));

        boolean authenticated = passwordEncoder.matches(request.getPassword(),
                user.getPassword());

        if(!authenticated) {
            throw new RuntimeException("password or username invalid");
        }

        String accessToken = generateToken(user, ACCESS_TOKEN_EXPIRATION, false);
        String refreshToken = generateToken(user, REFRESH_TOKEN_EXPIRATION, true);

        Cookie refreshTokenCookie  = new Cookie("refresh_token", refreshToken);
        refreshTokenCookie.setHttpOnly(true);
        refreshTokenCookie.setSecure(false);
        refreshTokenCookie.setPath("/");
        refreshTokenCookie.setMaxAge(7 * 24 * 60 * 60); // 7 ngày
        refreshTokenCookie.setAttribute("SameSite", "Strict");
        response.addCookie(refreshTokenCookie);

        var userResponse = UserResponse.builder()
                .email(user.getEmail())
                .userName(user.getUserName())
                .role(user.getRole())
                .build();


        return LoginResponse.<UserResponse>builder()
                .accessToken(accessToken)
                .data(userResponse)
                .build();
    }



    /*
    * tạo token
    * */
    public String generateToken(User user, long expiration, boolean isRefresh)  {
        try {
            System.out.println("UserName: " + user.getUserName());

            JWSHeader jwsHeader = new JWSHeader(JWSAlgorithm.HS512);

            JWTClaimsSet.Builder claimsSet = new JWTClaimsSet.Builder()
                    .subject(user.getUserName())
                    .issuer("your-app")
                    .issueTime(new Date())
                    .jwtID(UUID.randomUUID().toString())
                    .claim("typ", isRefresh ? "refresh" : "access")
                    .expirationTime(new Date(System.currentTimeMillis() + expiration));
            if(!isRefresh) {
                claimsSet.claim("scope", user.getRole());

            }
            JWTClaimsSet claimsBuild = claimsSet.build();
            SignedJWT signedJWT = new SignedJWT(jwsHeader, claimsBuild);

            signedJWT.sign(new MACSigner(SECRET_KEY));

            return signedJWT.serialize();
        } catch (JOSEException e) {
            throw new RuntimeException(e);
        }
    }

    /*
    * xác thực token
    * */
    private SignedJWT verifyToken(String token) throws ParseException, JOSEException {
        SignedJWT signedJWT = SignedJWT.parse(token);

        // Kiểm tra chữ ký
        if (!signedJWT.verify(new MACVerifier(SECRET_KEY.getBytes()))) {
            throw new RuntimeException("Token không hợp lệ!");
        }

        // Kiểm tra thời gian hết hạn
        Date expirationTime = signedJWT.getJWTClaimsSet().getExpirationTime();
        if (expirationTime == null || expirationTime.before(new Date())) {
            throw new JwtException("Token đã hết hạn!");
        }
        if(invalidatedTokenRepository.existsById(signedJWT.getJWTClaimsSet().getJWTID())){
            throw new JwtException("Token không còn hiệu lực!");
        }

        String tokenType = signedJWT.getJWTClaimsSet().getStringClaim("typ"); // Hoặc "scope"
        if ("refresh".equals(tokenType)) {
            throw new JwtException("Refresh Token không thể gọi API!");
        }

        return signedJWT;
    }

    /*
    * kiểm tra token
    * */
    public boolean introspects(String token) {
        try {
            verifyToken(token);
            return true; // Token hợp lệ
        } catch (JwtException | ParseException | JOSEException e) {
            System.err.println("Lỗi kiểm tra token: " + e.getMessage());
            return false; // Token không hợp lệ
        }
    }

    public String logout(LogoutRequestDto requestLogout, HttpServletRequest request, HttpServletResponse response) {
        try {
            // Lấy Refresh Token từ cookie
            Cookie refreshTokenCookie = WebUtils.getCookie(request, "refresh_token");

            if (refreshTokenCookie == null) {
                return "Không tìm thấy Refresh Token!";
            }
            String refreshToken = refreshTokenCookie.getValue();
            verifyRefreshToken(refreshToken);
            // Kiểm tra token
                //refresh token
            SignedJWT signedJWT = SignedJWT.parse(refreshToken);
            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();

            //access token
            SignedJWT signedJWTAccess = SignedJWT.parse(requestLogout.getToken());
            JWTClaimsSet claimsAccess = signedJWTAccess.getJWTClaimsSet();
            // Chỉ chấp nhận Refresh Token
            verifyToken(requestLogout.getToken());
            String tokenType = claims.getStringClaim("typ");
            if (!"refresh".equals(tokenType)) {
                throw new RuntimeException("Chỉ có Refresh Token mới được logout!");
            }

            // Lấy thông tin token
            String jti = claims.getJWTID();
            Date expiration = claims.getExpirationTime();

            if (jti == null || expiration == null) {
                throw new RuntimeException("Token không hợp lệ!");
            }

            // Kiểm tra xem token đã bị vô hiệu hóa chưa
            if (invalidatedTokenRepository.existsById(jti)) {
                return "Token này đã bị vô hiệu hóa trước đó!";
            }
            String jtiAccess = claimsAccess.getJWTID();
            Date expirationAccess = claimsAccess.getExpirationTime();
            // Vô hiệu hóa token
            invalidatedTokenRepository.save(new InvalidatedToken(jtiAccess, expirationAccess));
            invalidatedTokenRepository.save(new InvalidatedToken(jti, expiration));

            // Xóa Refresh Token trong cookie
            clearRefreshTokenCookie(response);

            return "Logout thành công!";
        } catch (ParseException e) {
            throw new RuntimeException("Lỗi phân tích token: " + e.getMessage());
        } catch (Exception e) {
            throw  new RuntimeException("error server");
        }
    }


    private void clearRefreshTokenCookie(HttpServletResponse response) {
        Cookie refreshTokenCookie = new Cookie("refresh_token", "");
        refreshTokenCookie.setHttpOnly(true);
        refreshTokenCookie.setSecure(false);
        refreshTokenCookie.setPath("/");
        refreshTokenCookie.setMaxAge(0);
        refreshTokenCookie.setAttribute("SameSite", "Strict");
        response.addCookie(refreshTokenCookie);
    }
    @Transactional
    public LoginResponse<UserResponse> refreshToken(HttpServletRequest request, HttpServletResponse response) {
        try {
            Cookie refreshTokenCookie = WebUtils.getCookie(request, "refresh_token");
            log.warn(" refresh token " + refreshTokenCookie);
            if (refreshTokenCookie == null) {
                throw new RuntimeException("Không tìm thấy Refresh Token trong cookie!");
            }

            String refreshToken = refreshTokenCookie.getValue();
            System.out.println("📌 Refresh Token nhận được: " + refreshToken);

            SignedJWT signedJWT = verifyRefreshToken(refreshToken);
            String username = signedJWT.getJWTClaimsSet().getSubject();

            User user = userRepository.findByUserName(username)
                    .orElseThrow(() -> new RuntimeException("User không tồn tại!"));

            System.out.println("✅ Refresh Token hợp lệ, tạo Access Token mới cho: " + user.getUserName());

            String jti = signedJWT.getJWTClaimsSet().getJWTID();
            if (!invalidatedTokenRepository.existsById(jti)) {
                invalidatedTokenRepository.save(new InvalidatedToken(jti, signedJWT.getJWTClaimsSet().getExpirationTime()));
            } else {
                System.out.println("⚠️ Refresh Token đã tồn tại trong bảng invalidated_token, bỏ qua.");
            }

            // Tạo token mới
            String newAccessToken = generateToken(user, ACCESS_TOKEN_EXPIRATION, false);
            String newRefreshToken = generateToken(user, REFRESH_TOKEN_EXPIRATION, true);

            // Cập nhật refresh token vào cookie
            Cookie newRefreshTokenCookie = new Cookie("refresh_token", newRefreshToken);
            newRefreshTokenCookie.setHttpOnly(true);
            newRefreshTokenCookie.setSecure(false);
            newRefreshTokenCookie.setPath("/");
            newRefreshTokenCookie.setMaxAge(7 * 24 * 60 * 60);
            response.addCookie(newRefreshTokenCookie);

            // Trả về access token mới
            var userResponse = UserResponse.builder()
                    .email(user.getEmail())
                    .userName(user.getUserName())
                    .role(user.getRole())
                    .build();

            System.out.println("✅ Access Token mới: " + newAccessToken);
            return LoginResponse.<UserResponse>builder()
                    .accessToken(newAccessToken)
                    .data(userResponse)
                    .build();
        } catch (Exception e) {
            System.out.println("❌ Lỗi refresh token: " + e.getMessage());
            throw new RuntimeException("Lỗi refresh token: " + e.getMessage());
        }
    }




    private SignedJWT verifyRefreshToken(String token) throws ParseException, JOSEException {
        SignedJWT signedJWT = SignedJWT.parse(token);
        if (!signedJWT.verify(new MACVerifier(SECRET_KEY.getBytes()))) {
            throw new RuntimeException("Refresh Token không hợp lệ!");
        }
        Date expirationTime = signedJWT.getJWTClaimsSet().getExpirationTime();
        if (expirationTime == null || expirationTime.before(new Date())) {
            throw new JwtException("Refresh Token đã hết hạn!");
        }
        if (invalidatedTokenRepository.existsById(signedJWT.getJWTClaimsSet().getJWTID())) {
            throw new JwtException("Refresh Token không còn hiệu lực!");
        }
        if (!"refresh".equals(signedJWT.getJWTClaimsSet().getStringClaim("typ"))) {
            throw new JwtException("Chỉ có Refresh Token mới được sử dụng để làm mới!");
        }
        return signedJWT;
    }


}
