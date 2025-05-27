package dev.duy.ismoke.configtest;

import static org.testng.Assert.*;

import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.Test;

import dev.duy.ismoke.config.JwtService;

public class JwtServiceTest {
    
    private JwtService jwtService;
    private UserDetails userDetails;
    
    @BeforeMethod
    public void setUp() {
        // Initialize JwtService
        jwtService = new JwtService();
        
        // Create a test UserDetails object
        userDetails = new User(
            "test@example.com", 
            "password", 
            new ArrayList<>()
        );
    }
    
    @Test
    public void testGenerateToken_ShouldCreateValidToken() {
        // Act
        String token = jwtService.generateToken(userDetails);
        
        // Assert
        assertNotNull(token);
        assertTrue(token.length() > 0);
    }
    
    @Test
    public void testExtractUsername_ShouldReturnCorrectUsername() {
        // Arrange
        String token = jwtService.generateToken(userDetails);
        
        // Act
        String username = jwtService.extractUsername(token);
        
        // Assert
        assertEquals(username, "test@example.com");
    }
    
    @Test
    public void testIsTokenValid_WithValidToken_ShouldReturnTrue() {
        // Arrange
        String token = jwtService.generateToken(userDetails);
        
        // Act
        boolean isValid = jwtService.isTokenValid(token, userDetails);
        
        // Assert
        assertTrue(isValid);
    }
    
    @Test
    public void testIsTokenValid_WithDifferentUser_ShouldReturnFalse() {
        // Arrange
        String token = jwtService.generateToken(userDetails);
        UserDetails differentUser = new User(
            "different@example.com", 
            "password", 
            new ArrayList<>()
        );
        
        // Act
        boolean isValid = jwtService.isTokenValid(token, differentUser);
        
        // Assert
        assertFalse(isValid);
    }
    
    @Test
    public void testGenerateTokenWithExtraClaims_ShouldIncludeExtraClaims() {
        // Arrange
        Map<String, Object> extraClaims = new HashMap<>();
        extraClaims.put("role", "ADMIN");
        extraClaims.put("userId", 123);

        extraClaims.put("extra", "extra claim");
        
        // Act
        String token = jwtService.generateToken(extraClaims, userDetails);
        
        // Assert
        assertEquals(jwtService.extractClaim(token, claims -> claims.get("role")), "ADMIN");
        assertEquals(jwtService.extractClaim(token, claims -> claims.get("userId")), 123);
        assertNotEquals(jwtService.extractClaim(token, claims -> claims.get("extra")), "not an extra claim");
    }
    
    @Test
    public void testExtractExpiration_ShouldReturnFutureDate() {
        // Arrange
        String token = jwtService.generateToken(userDetails);
        
        // Act
        Date expirationDate = jwtService.extractClaim(token, claims -> claims.getExpiration());
        
        // Assert
        assertTrue(expirationDate.after(new Date()));
    }
    
    @Test
    public void testExtractIssuedAt_ShouldReturnDateInPast() {
        // Arrange
        String token = jwtService.generateToken(userDetails);
        
        // Act
        Date issuedAt = jwtService.extractClaim(token, claims -> claims.getIssuedAt());
        
        // Assert
        assertTrue(issuedAt.before(new Date()) || issuedAt.equals(new Date()));
    }
}
