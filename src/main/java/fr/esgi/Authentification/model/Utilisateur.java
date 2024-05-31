package fr.esgi.Authentification.model;

import jakarta.persistence.*;
import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.*;
import lombok.experimental.SuperBuilder;

import java.util.HashSet;
import java.util.Set;

@Entity
@Getter
@Setter
@NoArgsConstructor
@Table(name = "utilisateurs", uniqueConstraints = {
        @UniqueConstraint(columnNames = "username"),
        @UniqueConstraint(columnNames = "adresseEmail")
        })
public class Utilisateur {

    @Id
    @GeneratedValue(strategy=GenerationType.IDENTITY)
    protected Long id;

    @NotBlank
    @Size(max = 50)
    protected String username;

    @Column(unique=true)
    @NotBlank
    @Email
    @Size(max = 50)
    protected String adresseEmail;

    @Size(max = 120)
    @NotBlank
    protected String motDePasse;

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(name = "utilisateur_roles",
            joinColumns = @JoinColumn(name = "utilisateur_id"),
            inverseJoinColumns = @JoinColumn(name = "role_id"))
    private Set<Role> roles = new HashSet<>();

    public Utilisateur(String username, String adresseEmail, String encode) {
        this.username = username;
        this.adresseEmail = adresseEmail;
        this.motDePasse = encode;
    }

}
