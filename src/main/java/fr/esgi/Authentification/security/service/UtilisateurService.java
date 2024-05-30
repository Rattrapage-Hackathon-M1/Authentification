package fr.esgi.Authentification.security.service;

import fr.esgi.Authentification.model.Utilisateur;

import java.util.Optional;

public interface UtilisateurService {
        Optional<Utilisateur> recupererUtilisateur(String username);
        Utilisateur ajouterUtilisateur(Utilisateur utilisateur);
}
