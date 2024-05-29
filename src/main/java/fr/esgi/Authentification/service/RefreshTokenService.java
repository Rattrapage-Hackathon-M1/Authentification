package fr.esgi.Authentification.service;

import fr.esgi.Authentification.business.Utilisateur;
import fr.esgi.Authentification.exception.TokenRefreshException;
import fr.esgi.Authentification.model.RefreshToken;
import fr.esgi.Authentification.repository.RefreshTokenRepository;
import fr.esgi.Authentification.repository.UtilisateurRepository;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.time.Instant;
import java.util.Optional;
import java.util.UUID;

@Service
public class RefreshTokenService {
    private Long refreshTokenDurationMs = 864000000L;
    @Autowired
    private RefreshTokenRepository refreshTokenRepository;
    @Autowired
    private UtilisateurRepository utilisateurRepository;

    public Optional<RefreshToken> findByToken(String token) {
        return refreshTokenRepository.findByToken(token);
    }

    public RefreshToken creerRefreshToken(Long userId) {
        Optional<Utilisateur> optionalUser = utilisateurRepository.findById(userId);
        if (optionalUser.isEmpty()) {
            throw new IllegalArgumentException("User not found with ID: " + userId);
        }

        Optional<RefreshToken> existingToken = refreshTokenRepository.findByUtilisateur(optionalUser.get());
        if (existingToken.isPresent()) {
            RefreshToken token = existingToken.get();
            token.setExpiryDate(Instant.now().plusMillis(refreshTokenDurationMs));
            token.setToken(UUID.randomUUID().toString());
            return refreshTokenRepository.save(token);
        } else {
            RefreshToken refreshToken = new RefreshToken();
            refreshToken.setUtilisateur(optionalUser.get());
            refreshToken.setExpiryDate(Instant.now().plusMillis(refreshTokenDurationMs));
            refreshToken.setToken(UUID.randomUUID().toString());
            return refreshTokenRepository.save(refreshToken);
        }
    }

    public RefreshToken verifierExpiration(RefreshToken token) {
        if (token.getExpiryDate().compareTo(Instant.now()) < 0) {
            refreshTokenRepository.delete(token);
            throw new TokenRefreshException();
        }
        return token;
    }

    @Transactional
    public int supprimerByUserId(Long userId) {
        return refreshTokenRepository.deleteByUtilisateur(utilisateurRepository.findById(userId).get());
    }
}
