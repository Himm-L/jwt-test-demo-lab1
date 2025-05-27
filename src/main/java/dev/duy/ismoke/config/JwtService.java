package dev.duy.ismoke.config;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

import java.security.Key;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

import javax.crypto.SecretKey;

import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;

@Service
public class JwtService {
    //will put in an .env file later
    private static final String JWT_SECRET = "jQeq1BrB1dFaB/+PFhqxN5fL5GW4G0vlUUxfDVvXI73HjjRwhxy6bzFQ9SCZUXDROVqJmrleDfGYEGvj0BKNMQ==";
    private static final int JWT_EXPIRE = 1000 * 60 * 60 * 24; //default: 24h in ms
    
    public String extractUsername(String token) {
        return extractClaim(token, Claims::getSubject);       
    }
    
    public <T> T extractClaim(String token, Function<Claims, T> claimsResolver) {
    	final Claims claims = extractAllClaims(token);
    	return claimsResolver.apply(claims);
    }
    
    public String generateToken(Map<String, Object> extraClaims,UserDetails userDetails) {
    return	Jwts.builder()
    	.claims()
    	.add(extraClaims)
    	.subject(userDetails.getUsername())
    	.issuedAt(new Date(System.currentTimeMillis()))
    	.expiration(new Date(System.currentTimeMillis() + JWT_EXPIRE))
    	.and()
    	.signWith(getSigningKey())
    	.compact();
    }

	public String generateToken(UserDetails userDetails){
		return generateToken(new HashMap<String,Object>() , userDetails);
	}

	public boolean isTokenValid(String token, UserDetails userDetails){
		final String username = extractUsername(token);
		return (username.equals(userDetails.getUsername()) && !isTokenExpired(token));
	}

	private boolean isTokenExpired(String token){
		return extractExpiration(token).before(new Date());
	}

	private Date extractExpiration(String token){
		return extractClaim(token, Claims::getExpiration);
	}

    private Claims extractAllClaims(String token) {        
    	Jws<Claims> jws = Jwts
    			.parser()
    			.verifyWith((SecretKey) getSigningKey())
    			.build()
    			.parseSignedClaims(token);
        return jws.getPayload();
    }

	private Key getSigningKey() {
		byte[] keyBytes = Decoders.BASE64.decode(JWT_SECRET);
		return Keys.hmacShaKeyFor(keyBytes);
	}
    
    
}
