package fr.esgi.Authentification.security.jwt;

import java.security.Key;
import java.util.Date;
import java.util.List;
import java.util.Set;

import fr.esgi.Authentification.business.Utilisateur;
import fr.esgi.Authentification.model.Role;
import fr.esgi.Authentification.repository.UtilisateurRepository;
import fr.esgi.Authentification.security.service.impl.UtilisateurDetailsImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtTokenProvider {
    private static final Logger logger = LoggerFactory.getLogger(JwtTokenProvider.class);
    private final UtilisateurRepository utilisateurRepository;
    @Value("${esgi.app.jwtSecret}")
    private String JWT_SECRET;
    @Value("${esgi.app.jwtExpirationMs}")
    private int JWT_EXPIRATION;

    public JwtTokenProvider(UtilisateurRepository utilisateurRepository) {
        this.utilisateurRepository = utilisateurRepository;
    }

    public String generateToken(Authentication authentication) {
        UtilisateurDetailsImpl utilisateur = (UtilisateurDetailsImpl) authentication.getPrincipal();
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + JWT_EXPIRATION);

        List<String> roles = utilisateur.getAuthorities()
                .stream()
                .map(role -> role.getAuthority())
                .toList();
        return Jwts.builder()
                .setSubject(authentication.getName())
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .signWith(key(), SignatureAlgorithm.HS512)
                .claim("roles", roles)
                .compact();
    }

    private Key key() {
        byte[] keyBytes = Decoders.BASE64.decode(JWT_SECRET);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String generateTokenFromUsername(String username) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + JWT_EXPIRATION);
        Utilisateur utilisateur = utilisateurRepository.findByAdresseEmail(username).get();
        Set<Role> rolesSet = utilisateur.getRoles();
        List<String> roles = rolesSet.stream()
                .map(role -> role.getName())
                .map(Enum::name)
                .toList();
        return Jwts.builder()
                .setSubject(username)
                .setIssuedAt(now)
                .setExpiration(expiryDate)
                .signWith(key(), SignatureAlgorithm.HS512)
                .claim("roles", roles)
                .compact();
    }

    public String getUserNameFromJwtToken(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key())
                .build()
                .parseClaimsJws(token)
                .getBody()
                .getSubject();
    }

    public boolean validateJwtToken(String authToken) {
        try {
            Jwts.parserBuilder().setSigningKey(key()).build().parse(authToken);
            return true;
        } catch (MalformedJwtException e) {
            logger.error("Invalid JWT token: {}", e.getMessage());
        } catch (ExpiredJwtException e) {
            logger.error("JWT token is expired: {}", e.getMessage());
        } catch (UnsupportedJwtException e) {
            logger.error("JWT token is unsupported: {}", e.getMessage());
        } catch (IllegalArgumentException e) {
            logger.error("JWT claims string is empty: {}", e.getMessage());
        }

        return false;
    }
}
