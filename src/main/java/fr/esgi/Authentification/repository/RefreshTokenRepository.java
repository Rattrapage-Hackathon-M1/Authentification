package fr.esgi.Authentification.repository;

import fr.esgi.Authentification.business.Utilisateur;
import fr.esgi.Authentification.model.RefreshToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RefreshTokenRepository extends JpaRepository<RefreshToken, Long> {
    Optional<RefreshToken> findByToken(String token);

    Optional<RefreshToken> findByUtilisateur(Utilisateur utilisateur);

    @Query(
            value = "SELECT u FROM RefreshToken rt JOIN Utilisateur u ON u.id = rt.utilisateur.id " +
                    "WHERE rt.token = :token"
    )
    Optional<Utilisateur> findUserByToken(String token);

    @Modifying
    int deleteByUtilisateur(Utilisateur utilisateur);
}
