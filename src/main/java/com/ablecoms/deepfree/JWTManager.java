package com.ablecoms.deepfree;

import java.io.UnsupportedEncodingException;
import java.util.Date;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.util.StringUtils;

import com.auth0.jwt.JWT;
import com.auth0.jwt.JWTCreator.Builder;
import com.auth0.jwt.JWTVerifier;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.exceptions.JWTCreationException;
import com.auth0.jwt.exceptions.JWTDecodeException;
import com.auth0.jwt.interfaces.DecodedJWT;
import com.auth0.jwt.interfaces.Verification;

/**
 * JWT Manager
 * 
 * @author deepfree@ablecoms.com
 */
public class JWTManager {
	private static final Logger logger = LoggerFactory.getLogger(JWTManager.class);

	Algorithm algorithm = null;

	/**
	 * 생성자
	 * @param hmac256Secret HMAC256 Sign Secret
	 */
	public JWTManager(String hmac256Secret) {
		super();
		try {
			this.algorithm = Algorithm.HMAC256(hmac256Secret);
		} catch (IllegalArgumentException | UnsupportedEncodingException e) {
			logger.error("FAILED TO CONSTRUCT JWTManager. {}: {}", e.getClass().getCanonicalName(), e.getMessage());
			throw new RuntimeException("FAILED TO CONSTRUCT JWTManager - " + e.getMessage(), e);
		}
	}

	/**
	 * 토큰생성 (지정된 필드만 적용)
	 * @param issuer 발행자 
	 * @param subject 토큰제목 - 토큰의 Principal
	 * @param audience 토큰대상자
	 * @param expiresAt 토큰만료일시 
	 * @param notBefore 토큰유효시작일시 
	 * @param issuedAt 토큰발행일시 
	 * @param jwtId 토큰고유식별자
	 * @param customHeaderClaims Custom Header Claims
	 * @param customPayloadClaims Custom Payload Claims
	 * @return JWT String
	 */
	public String buildJWT(String issuer, String subject, String audience, Date expiresAt, Date notBefore,
			Date issuedAt, String jwtId, Map<String, Object> customHeaderClaims, Map<String, String> customPayloadClaims) {
		try {
			Builder builder = JWT.create();
			
			if(customHeaderClaims != null) {
				builder.withHeader(customHeaderClaims);
			}
			if(customPayloadClaims != null) {
				for (String key : customPayloadClaims.keySet()) {
					String claimValue = customPayloadClaims.get(key);
					builder.withClaim(key, claimValue);
				}
			}
			
			if (!StringUtils.isEmpty(issuer)) { builder.withIssuer(issuer); }
			if (!StringUtils.isEmpty(subject)) { builder.withSubject(subject); }
			if (!StringUtils.isEmpty(audience)) { builder.withAudience(audience); }
			if (expiresAt != null) { builder.withExpiresAt(expiresAt); }
			if (notBefore != null) { builder.withNotBefore(notBefore); }
			if (issuedAt != null) { builder.withIssuedAt(issuedAt); }
			if (!StringUtils.isEmpty(jwtId)) { builder.withJWTId(jwtId); }
			
			return builder.sign(algorithm);
		} catch (JWTCreationException e) {
			logger.error("FAILED TO CREATE JWT. {}: {}", e.getClass().getCanonicalName(), e.getMessage());
			throw new RuntimeException("FAILED TO CREATE JWT - " + e.getMessage(), e);
		}
	}

	/**
	 * 알고리즘으로 검증기용 검증스팩 생성. 필요시 추가룰을 지정하고 build()로 Verifier를 획득 
	 * @param issuer 발급자 (전달시 검사) 
	 * @param subject 토큰제목 (전달시 검사) 
	 * @param jwtId 토큰고유식별자 (전달시 검사)
	 * @param applyTimeValidation 시간을 검증할 것인가?
	 * @param leewaySec 시간검증시 적용할 leeway 시간(초) - 예: 1이면 만료후 1초간도 유효로 계산
	 * @return build()로 검증기를 생성할 수 있는 검증스펙  
	 */
	public Verification buildVerification(String issuer, String subject, String jwtId,
			boolean applyTimeValidation, int leewaySec) {
		Verification verification = JWT.require(algorithm);
		
		if(!StringUtils.isEmpty(issuer)) { verification.withIssuer(issuer); }
		if(!StringUtils.isEmpty(subject)) { verification.withSubject(subject); }
		if(!StringUtils.isEmpty(jwtId)) { verification.withJWTId(jwtId); }
		
		if(applyTimeValidation) {
			//Time Validation
			verification.acceptLeeway(leewaySec);
		}
		
		return verification;
	}
	
	/**
	 * JWT문자열에서 디코딩된 정보를 획득 (검증은 안함) 
	 * @param token JWT 토큰 
	 * @return 디코딩된 JWT 정보 
	 */
	public DecodedJWT decodeJWT(String token) {
		try {
		    DecodedJWT decodedJWT = JWT.decode(token);
		    return decodedJWT;
		} catch (JWTDecodeException e){
			logger.error("FAILED TO CREATE JWT. {}: {} - {}", e.getClass().getCanonicalName(), e.getMessage(), token);
			throw new RuntimeException("FAILED TO CREATE JWT - " + e.getMessage(), e);
		}
	}
	
	/**
	 * JWT문자열을 검증하고 디코딩된 정보를 획득
	 * @param token 검증할 JWT 토큰 
	 * @param issuer 발급자 (전달시 검사) 
	 * @param subject 토큰제목 (전달시 검사) 
	 * @param jwtId 토큰고유식별자 (전달시 검사)
	 * @param applyTimeValidation 시간을 검증할 것인가?
	 * @param leewaySec 시간검증시 적용할 leeway 시간(초) - 예: 1이면 만료후 1초간도 유효로 계산
	 * @return 검증호 디코딩된 JWT 정보 
	 */
	public DecodedJWT decodeJWTWithVerification(String token,
			String issuer, String subject, String jwtId,
			boolean applyTimeValidation, int leewaySec) {
		 try {
			 JWTVerifier verifier = buildVerification(issuer, subject, jwtId, applyTimeValidation, leewaySec).build();
			 return verifier.verify(token);
		 } catch(Exception e) { 
			 logger.error("FAILED TO VERIFY JWT. {}: {} - {}", e.getClass().getCanonicalName(), e.getMessage(), token);
			 throw new RuntimeException("FAILED TO VERIFY JWT - " + e.getMessage(), e);
		 }
	}
	
}
