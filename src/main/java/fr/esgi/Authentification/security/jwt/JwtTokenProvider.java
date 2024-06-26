package fr.esgi.Authentification.security.jwt;

import java.security.Key;
import java.util.Date;
import java.util.List;
import java.util.Set;

import fr.esgi.Authentification.exception.CustomExpiredJwtTokenException;
import fr.esgi.Authentification.exception.CustomMalformedJwtException;
import fr.esgi.Authentification.exception.CustomTechnicalJwtException;
import fr.esgi.Authentification.model.ERole;
import fr.esgi.Authentification.model.Utilisateur;
import fr.esgi.Authentification.model.Role;
import fr.esgi.Authentification.repository.UtilisateurRepository;
import fr.esgi.Authentification.security.service.impl.UtilisateurDetailsImpl;
import io.jsonwebtoken.security.SignatureException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;
import io.jsonwebtoken.*;
import io.jsonwebtoken.io.Decoders;
import io.jsonwebtoken.security.Keys;

@Component
public class JwtTokenProvider {
    private static final Logger logger = LoggerFactory.getLogger(JwtTokenProvider.class);
    private final UtilisateurRepository utilisateurRepository;
    @Value("${esgi.app.jwtSecret}")
    private String jwtSecret;
    @Value("${esgi.app.jwtExpirationMs}")
    private int jwtExpiration;

    public JwtTokenProvider(UtilisateurRepository utilisateurRepository) {
        this.utilisateurRepository = utilisateurRepository;
    }

    public String generateToken(Authentication authentication) {
        UtilisateurDetailsImpl utilisateur = (UtilisateurDetailsImpl) authentication.getPrincipal();
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + jwtExpiration);

        List<String> roles = utilisateur.getAuthorities()
                .stream()
                .map(GrantedAuthority::getAuthority)
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
        byte[] keyBytes = Decoders.BASE64.decode(jwtSecret);
        return Keys.hmacShaKeyFor(keyBytes);
    }

    public String generateTokenFromUsername(String username) {
        Date now = new Date();
        Date expiryDate = new Date(now.getTime() + jwtExpiration);
        Utilisateur utilisateur = utilisateurRepository.findByUsername(username)
                .get();
        Set<Role> rolesSet = utilisateur.getRoles();
        List<String> roles = rolesSet.stream()
                .map(Role::getName)
                .map(ERole::name)
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
            Jwts.parserBuilder()
                    .setSigningKey(key())
                    .build()
                    .parse(authToken);
            return true;
        } catch (MalformedJwtException exception) {
            logger.error("Invalid JWT token: {}", exception.getMessage());
            throw new CustomMalformedJwtException();
        } catch (ExpiredJwtException exception) {
            logger.error("JWT token is expired: {}", exception.getMessage());
            throw new CustomExpiredJwtTokenException();
        } catch (UnsupportedJwtException exception) {
            logger.error("JWT token is unsupported: {}", exception.getMessage());
            throw new CustomTechnicalJwtException();
        } catch (IllegalArgumentException exception) {
            logger.error("JWT claims string is empty: {}", exception.getMessage());
            throw new CustomTechnicalJwtException();
        } catch (SignatureException exception) {
            logger.error("JWT signature does not match: {}", exception.getMessage());
            throw new CustomTechnicalJwtException();
        }
    }
}
