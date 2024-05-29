package fr.esgi.Authentification.service.impl;

import com.fasterxml.jackson.annotation.JsonIgnore;
import fr.esgi.Authentification.business.Utilisateur;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

public class UtilisateurDetailsImpl implements UserDetails {
    private static final long serialVersionUID = 1L;

    private Long id;

    private String email;

    @JsonIgnore
    private String password;

    private Collection<? extends GrantedAuthority> authorities;

    public UtilisateurDetailsImpl(Long id, String email, String password,
                                  Collection<? extends GrantedAuthority> authorities) {
        this.id = id;
        this.email = email;
        this.password = password;
        this.authorities = authorities;
    }

    public static UtilisateurDetailsImpl build(Utilisateur utilisateur) {
        List<GrantedAuthority> authorities = utilisateur.getRoles().stream()
                .map(role -> new SimpleGrantedAuthority(role.getName().name()))
                .collect(Collectors.toList());

        return new UtilisateurDetailsImpl(utilisateur.getId(),
                utilisateur.getAdresseEmail(),
                utilisateur.getMotDePasse(),
                authorities);
    }

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    public Long getId() {
        return id;
    }

    public String getEmail() {
        return email;
    }

    @Override
    public String getPassword() {
        return password;
    }

    @Override
    public String getUsername() {
        return email;
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    @Override
    public boolean isEnabled() {
        return true;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o)
            return true;
        if (o == null || getClass() != o.getClass())
            return false;
        UtilisateurDetailsImpl user = (UtilisateurDetailsImpl) o;
        return Objects.equals(id, user.id);
    }
}
