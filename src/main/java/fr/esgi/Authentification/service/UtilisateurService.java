package fr.esgi.Authentification.service;

import fr.esgi.Authentification.business.Utilisateur;

import java.util.Optional;

public interface UtilisateurService {
        Optional<Utilisateur> recupererUtilisateur(String username);
        Utilisateur ajouterUtilisateur(Utilisateur utilisateur);
}
