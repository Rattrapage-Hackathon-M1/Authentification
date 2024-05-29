package fr.esgi.Authentification.repository;


import fr.esgi.Authentification.business.Utilisateur;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UtilisateurRepository extends JpaRepository<Utilisateur, Long>{
    Optional<Utilisateur> findByAdresseEmail(String adresseEmail);
}
