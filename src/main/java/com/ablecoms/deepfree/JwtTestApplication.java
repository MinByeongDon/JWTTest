package com.ablecoms.deepfree;

import java.util.Date;

import org.joda.time.DateTime;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.auth0.jwt.interfaces.DecodedJWT;

public class JwtTestApplication {

	private static final Logger logger = LoggerFactory.getLogger(JwtTestApplication.class);

	public static void main(String[] args) {
		JWTManager jwtManager = new JWTManager("hmac256Secret");
		
		logger.debug("jwt build ========================");
		DateTime now = DateTime.now();
		String issuer = "arykorea";
		String subject = "marco:hardwareId:1234XXX";
		String audience = null;
		DateTime expiresAt = now.plusDays(365);
		DateTime notBefore = now;
		DateTime issuedAt = now;
		String jwtId = null;
		String jwt = jwtManager.buildJWT(issuer, subject, audience, 
				expiresAt.toDate(), notBefore.toDate(), issuedAt.toDate(),
				jwtId, null, null);
		logger.debug(" jwt생성: {}", jwt);
		
		{
			logger.debug("jwt Decode ========================");
			DecodedJWT decodeJWT = jwtManager.decodeJWT(jwt);
			logger.debug(" decodeJWT.issuer: {}", decodeJWT.getIssuer());
			logger.debug(" decodeJWT.subject: {}", decodeJWT.getSubject());
		}
		
		{
			logger.debug("jwt Decode With Verification ========================");
			DecodedJWT decodeJWT = jwtManager.decodeJWTWithVerification(jwt, "arykorea", null, null, true, 30);
			logger.debug(" decodeJWT.issuer: {}", decodeJWT.getIssuer());
			logger.debug(" decodeJWT.subject: {}", decodeJWT.getSubject());
		}
		
		try {
			logger.debug("INVALID TOKEN ========================");
			DecodedJWT decodeJWT = jwtManager.decodeJWTWithVerification("XXXX", "arykorea", null, null, true, 30);
			logger.debug(" decodeJWT.issuer: {}", decodeJWT.getIssuer());
			logger.debug(" decodeJWT.subject: {}", decodeJWT.getSubject());
		} catch(Exception e) { logger.debug("{}: {}", e.getClass().getCanonicalName(), e.getMessage()); }
		
		try {
			logger.debug("INVALID TOKEN Signature ========================");
			DecodedJWT decodeJWT = jwtManager.decodeJWTWithVerification(jwt+"XXXX", "arykorea", null, null, true, 30);
			logger.debug(" decodeJWT.issuer: {}", decodeJWT.getIssuer());
			logger.debug(" decodeJWT.subject: {}", decodeJWT.getSubject());
		} catch(Exception e) { logger.debug("{}: {}", e.getClass().getCanonicalName(), e.getMessage()); }

		try {
			logger.debug("INVALID TOKEN Issuer ========================");
			DecodedJWT decodeJWT = jwtManager.decodeJWTWithVerification(jwt, "arykoreaXXXX", null, null, true, 30);
			logger.debug(" decodeJWT.issuer: {}", decodeJWT.getIssuer());
			logger.debug(" decodeJWT.subject: {}", decodeJWT.getSubject());
		} catch(Exception e) { logger.debug("{}: {}", e.getClass().getCanonicalName(), e.getMessage()); }
		
		try {
			logger.debug("INVALID TOKEN Expired ========================");
			Date yesterday = DateTime.now().minusDays(1).toDate();
			String oldJwt = jwtManager.buildJWT(issuer, subject, audience, 
					yesterday, yesterday, yesterday,
					jwtId, null, null);
			DecodedJWT decodeJWT = jwtManager.decodeJWTWithVerification(oldJwt, "arykorea", null, null, true, 30);
			logger.debug(" decodeJWT.issuer: {}", decodeJWT.getIssuer());
			logger.debug(" decodeJWT.subject: {}", decodeJWT.getSubject());
		} catch(Exception e) { logger.debug("{}: {}", e.getClass().getCanonicalName(), e.getMessage()); }

	}
}
