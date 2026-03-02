package com.jwt.security;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import javax.crypto.SecretKey;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;

@Service
public class JwtService {

	// 🔐 Secret key (minimum 256 bits for HS256)
	private String SECRET = "TaK+HaV^uvCHEFsEVfypW#7g9^k*Z8$V";

	// 🔑 Generate signing key
	private SecretKey getSigningKey() {
		return Keys.hmacShaKeyFor(SECRET.getBytes());
	}

	// ✅ Generate Token
	public String generateToken(String username) {
		Map<String,Object> claims = new HashMap<>();
		return createToken(claims,username);
	}

	private String createToken(Map<String, Object> claims, String subject) {
		return Jwts.builder()
				.claims(claims)
				.subject(subject)
				.header().empty().add("typ","jwt")
				.and()
				.issuedAt(new Date(System.currentTimeMillis()))
				.expiration(new Date(System.currentTimeMillis()+1000*60*60))//5 Mins
				.signWith(getSigningKey())
				.compact();
	}

	// ✅ Extract Username
	public String extractUsername(String token) {
		return extractClaim(token).getSubject();
	}

	// ✅ Validate Token (UPDATED)
	public boolean isTokenValid(String token, UserDetails userDetails) {
		final String username = extractUsername(token);
		return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
	}

	// 🔍 Check Expiry
	private boolean isTokenExpired(String token) {
		return extractExpiration(token).before(new Date());
	}

	// 🔍 Extract Expiration
	private Date extractExpiration(String token) {
		return extractClaim(token).getExpiration();
	}

	// 🔍 Generic Claim Extractor
	public Claims extractClaim(String token) {
		return Jwts.parser()
				.verifyWith(getSigningKey())
				.build()
				.parseSignedClaims(token)
				.getPayload();
	}

	// 📦 Extract All Claims
	private Claims extractAllClaims(String token) {
		return Jwts.parser()
				.verifyWith(getSigningKey())
				.build()
				.parseSignedClaims(token)
				.getPayload();
	}
}