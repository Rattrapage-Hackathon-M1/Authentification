package fr.esgi.Authentification.hexa.domain.persistence.adapter;

import fr.esgi.Authentification.hexa.domain.Test;
import fr.esgi.Authentification.hexa.domain.spi.IDao;
import fr.esgi.Authentification.repository.UtilisateurRepository;

public class UtilisateurDao implements IDao {
    private final UtilisateurRepository userRepository;

    public UtilisateurDao(UtilisateurRepository userRepository) {
        this.userRepository = userRepository;
    }

    @Override
    public Test add(Test newTest) {
        return null;
    }
}
