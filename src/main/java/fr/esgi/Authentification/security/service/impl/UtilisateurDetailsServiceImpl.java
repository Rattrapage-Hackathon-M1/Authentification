package fr.esgi.Authentification.security.service.impl;

import fr.esgi.Authentification.business.Utilisateur;
import fr.esgi.Authentification.repository.UtilisateurRepository;
import jakarta.transaction.Transactional;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class UtilisateurDetailsServiceImpl implements UserDetailsService {

    @Autowired
    UtilisateurRepository utilisateurRepository;

    @Override
    @Transactional
    public UserDetails loadUserByUsername(String adresseMail) throws UsernameNotFoundException {
        if (adresseMail.trim().isEmpty()) {
            throw new UsernameNotFoundException("L'adresse mail ne peut pas être vide");
        }
        Utilisateur utilisateur = utilisateurRepository.findByAdresseEmail(adresseMail)
                .orElseThrow(() -> new UsernameNotFoundException("Utilisateur " + adresseMail + " introuvable"));
        return UtilisateurDetailsImpl.build(utilisateur);
    }
}
