package fr.esgi.Authentification.controller;

import fr.esgi.Authentification.model.Utilisateur;
import fr.esgi.Authentification.exception.TokenRefreshException;
import fr.esgi.Authentification.model.ERole;
import fr.esgi.Authentification.model.RefreshToken;
import fr.esgi.Authentification.model.Role;
import fr.esgi.Authentification.payload.request.ChangePasswordRequest;
import fr.esgi.Authentification.payload.request.LoginRequest;
import fr.esgi.Authentification.payload.request.SignUpRequest;
import fr.esgi.Authentification.payload.request.TokenRefreshRequest;
import fr.esgi.Authentification.payload.response.JwtResponse;
import fr.esgi.Authentification.payload.response.MessageResponse;
import fr.esgi.Authentification.payload.response.TokenRefreshResponse;
import fr.esgi.Authentification.repository.RoleRepository;
import fr.esgi.Authentification.repository.UtilisateurRepository;
import fr.esgi.Authentification.security.jwt.JwtTokenProvider;
import fr.esgi.Authentification.security.service.RefreshTokenService;
import fr.esgi.Authentification.security.service.TokenBlacklist;
import fr.esgi.Authentification.security.service.impl.UtilisateurDetailsImpl;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
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
    @Autowired
    private TokenBlacklist tokenBlacklist;

    Logger logger = LoggerFactory.getLogger(UtilisateurController.class);

    @PostMapping("/signup")
    public ResponseEntity<?> inscriptionUtilisateur(@Valid @RequestBody SignUpRequest signUpRequest) {
        if (utilisateurRepository.existsByAdresseEmail(signUpRequest.getEmail())) {
            return ResponseEntity.badRequest().body("Erreur : l'adresse email est déjà prise");
        }
        if (utilisateurRepository.existsByUsername(signUpRequest.getUsername())) {
            return ResponseEntity.badRequest().body("Erreur : le username est déjà pris");
        }

        Utilisateur utilisateur = new Utilisateur(
                signUpRequest.getUsername(),
                signUpRequest.getEmail(),
                encoder.encode(signUpRequest.getPassword()));

        Set<String> strRoles = signUpRequest.getRole();
        Set<Role> roles = new HashSet<>();

        if (strRoles == null) {
            Role role = roleRepository.findByName(ERole.ROLE_USER)
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
                        Role userRole = roleRepository.findByName(ERole.ROLE_USER)
                                .orElseThrow(() -> new RuntimeException("Erreur : le rôle n'est pas trouvé."));
                        roles.add(userRole);
                }
            });
        }

        utilisateur.setRoles(roles);
        utilisateurRepository.save(utilisateur);
        return ResponseEntity.ok(new MessageResponse("Utilisateur enregistré avec succès !"));
    }

    @PostMapping("/login")
    public ResponseEntity<?> connexionUtilisateur(@Valid @RequestBody LoginRequest loginRequest) {
        try {
            Authentication authentication = authenticationManager
                    .authenticate(new UsernamePasswordAuthenticationToken(loginRequest.getUsername(),
                            loginRequest.getPassword()));
            SecurityContextHolder.getContext().setAuthentication(authentication);
            UtilisateurDetailsImpl userDetails = (UtilisateurDetailsImpl) authentication.getPrincipal();
            String token = jwtTokenProvider.generateToken(authentication);
            List<String> roles = userDetails.getAuthorities()
                    .stream()
                    .map(item -> item.getAuthority())
                    .toList();
            RefreshToken refreshToken = refreshTokenService.creerRefreshToken(userDetails.getId());
            return ResponseEntity.ok(new JwtResponse(
                    token,
                    refreshToken.getToken(),
                    userDetails.getId(),
                    userDetails.getUsername(),
                    userDetails.getEmail(),
                    roles));
        } catch (Exception e) {
            logger.error("Erreur d'authentification: " + e.getMessage());
            return ResponseEntity.status(401).body("Unauthorized");
        }
    }

    @GetMapping("/verifytoken")
    public ResponseEntity<?> verifyToken(@RequestHeader("Authorization") String tokenHeader) {
        boolean isValid = validateToken(tokenHeader);

        if (isValid) {
            return ResponseEntity.ok(new MessageResponse("Token is valid"));
        } else {
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body(new MessageResponse("Token is invalid or expired"));
        }
    }

    private boolean validateToken(String header) {
        if (header != null && header.startsWith("Bearer ")) {
            String jwtToken = header.substring(7); // Remove "Bearer " prefix
            try {
                return jwtTokenProvider.validateJwtToken(jwtToken);
            } catch (Exception e) {
                logger.error("Error validating token: " + e.getMessage());
                return false;
            }
        }
        return false;
    }

    @PostMapping("/logout")
    public ResponseEntity<?> deconnexionUtilisateur(HttpServletRequest request) {
        String token = extraireToken(request);
        SecurityContextHolder.clearContext();
        return ResponseEntity.ok("Vous êtes déconnecté");
    }

    @PostMapping("/refreshtoken")
    public ResponseEntity<?> refreshtoken(@Valid @RequestBody TokenRefreshRequest request) {
        String requestRefreshToken = request.getRefreshToken();

        return refreshTokenService.findByToken(requestRefreshToken)
                .map(refreshTokenService::verifierExpiration)
                .map(RefreshToken::getUtilisateur)
                .map(user -> {
                    String token = jwtTokenProvider.generateTokenFromUsername(((Utilisateur) user).getAdresseEmail());
                    return ResponseEntity.ok(new TokenRefreshResponse(token, requestRefreshToken));
                })
                .orElseThrow(() -> new TokenRefreshException());
    }

    @PostMapping("/changepassword")
    @PreAuthorize("hasRole('USER') or hasRole('ADMIN')")
    public ResponseEntity<?> changePassword(
            @Valid @RequestBody ChangePasswordRequest changePasswordRequest,
            HttpServletRequest request) {
        UtilisateurDetailsImpl userDetails = (UtilisateurDetailsImpl) SecurityContextHolder.getContext()
                .getAuthentication()
                .getPrincipal();
        Utilisateur user = utilisateurRepository.findById(userDetails.getId())
                .orElseThrow(() -> new RuntimeException(
                        "Error: User not found."));

        if (!encoder.matches(changePasswordRequest.getOldPassword(),
                user.getMotDePasse())) {
            return ResponseEntity.badRequest()
                    .body(new MessageResponse(
                            "Error: Old password is incorrect."));
        }

        user.setMotDePasse(encoder.encode(changePasswordRequest.getNewPassword()));
        utilisateurRepository.save(user);

        // Invalidate the current authentication token
        String token = extraireToken(request);
        tokenBlacklist.blacklistToken(token);

        return ResponseEntity.ok(new MessageResponse("Password changed successfully!"));
    }

    private String extraireToken(HttpServletRequest request) {
        String bearerToken = request.getHeader("Authorization");
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) {
            return bearerToken.substring(7);
        }
        return null;
    }
}
