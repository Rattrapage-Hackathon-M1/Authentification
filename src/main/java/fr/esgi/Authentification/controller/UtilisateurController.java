package fr.esgi.Authentification.controller;

import fr.esgi.Authentification.business.Utilisateur;
import fr.esgi.Authentification.model.ERole;
import fr.esgi.Authentification.model.RefreshToken;
import fr.esgi.Authentification.model.Role;
import fr.esgi.Authentification.payload.request.LoginRequest;
import fr.esgi.Authentification.payload.request.SignUpRequest;
import fr.esgi.Authentification.payload.response.JwtResponse;
import fr.esgi.Authentification.repository.RoleRepository;
import fr.esgi.Authentification.repository.UtilisateurRepository;
import fr.esgi.Authentification.security.jwt.JwtTokenProvider;
import fr.esgi.Authentification.service.RefreshTokenService;
import fr.esgi.Authentification.service.impl.UtilisateurDetailsImpl;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import lombok.AllArgsConstructor;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.web.bind.annotation.*;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

@CrossOrigin(origins = "*", maxAge = 3600)
@RestController
@RequestMapping("/api/auth")
@AllArgsConstructor
public class UtilisateurController {
    @Autowired
    private JwtTokenProvider jwtTokenProvider;
    @Autowired
    AuthenticationManager authenticationManager;
    @Autowired
    private PasswordEncoder encoder;
    @Autowired
    private RoleRepository roleRepository;
    @Autowired
    private UtilisateurRepository utilisateurRepository;
    @Autowired
    private RefreshTokenService refreshTokenService;

    @PostMapping("/signup")
    public ResponseEntity<?> inscriptionUtilisateur(@Valid @RequestBody SignUpRequest signUpRequest) {
        if (utilisateurRepository.findByAdresseEmail(signUpRequest.getEmail()).isPresent()) {
            return ResponseEntity.badRequest().body("L'utilisateur existe déjà");
        }
        Utilisateur utilisateur = new Utilisateur(
                signUpRequest.getNom(),
                signUpRequest.getPrenom(),
                signUpRequest.getEmail(),
                encoder.encode(signUpRequest.getPassword()));

        Set<String> strRoles = signUpRequest.getRole();
        Set<Role> roles = new HashSet<>();

        if (strRoles == null) {
            Role role = roleRepository.findByName(ERole.ROLE_EMPLOYE)
                    .orElseThrow(() -> new RuntimeException("Erreur : le rôle n'est pas trouvé."));
            roles.add(role);
        } else {
            strRoles.forEach(role -> {
                switch (role) {
                    case "admin":
                        Role adminRole = roleRepository.findByName(ERole.ROLE_ADMIN)
                                .orElseThrow(() -> new RuntimeException("Erreur : le rôle n'est pas trouvé."));
                        roles.add(adminRole);
                        break;
                    default:
                        Role userRole = roleRepository.findByName(ERole.ROLE_EMPLOYE)
                                .orElseThrow(() -> new RuntimeException("Erreur : le rôle n'est pas trouvé."));
                        roles.add(userRole);
                }
            });
        }

        utilisateur.setRoles(roles);
        utilisateurRepository.save(utilisateur);
        return ResponseEntity.ok(utilisateur);
    }

    @PostMapping("/login")
    public ResponseEntity<?> connexionUtilisateur(@Valid @RequestBody LoginRequest loginRequest) {
        Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getEmail(), loginRequest.getPassword()));
        SecurityContextHolder.getContext().setAuthentication(authentication);
        String token = jwtTokenProvider.generateToken(authentication);
        UtilisateurDetailsImpl userDetails = (UtilisateurDetailsImpl) authentication.getPrincipal();
        List<String> roles = userDetails.getAuthorities().stream()
                .map(item -> item.getAuthority())
                .toList();
        RefreshToken refreshToken = refreshTokenService.creerRefreshToken(userDetails.getId());
        return ResponseEntity.ok(new JwtResponse(
                token,
                refreshToken.getToken(),
                userDetails.getId(),
                userDetails.getEmail(),
                roles));
    }

    @PostMapping("/logout")
    public ResponseEntity<?> deconnexionUtilisateur(HttpServletRequest request) {
        String token = extraireToken(request);
        SecurityContextHolder.clearContext();
        return ResponseEntity.ok("Vous êtes déconnecté");
    }

    private String extraireToken(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }

    public static class JwtAuthenticationResponse {
        private String accessToken;
        private String tokenType = "Bearer";

        public JwtAuthenticationResponse(String accessToken) {
            this.accessToken = accessToken;
        }

        public String getAccessToken() {
            return accessToken;
        }

        public void setAccessToken(String accessToken) {
            this.accessToken = accessToken;
        }

        public String getTokenType() {
            return tokenType;
        }

        public void setTokenType(String tokenType) {
            this.tokenType = tokenType;
        }
    }
}
