package fr.esgi.Authentification.repository;

import fr.esgi.Authentification.model.ERole;
import fr.esgi.Authentification.model.Role;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface RoleRepository extends JpaRepository<Role, Long>{
    Optional<Role> findByName(ERole name);
}
