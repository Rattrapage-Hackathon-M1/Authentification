//package fr.esgi.Authentification.configuration;
//
//import fr.esgi.Authentification.model.ERole;
//import fr.esgi.Authentification.model.Role;
//import fr.esgi.Authentification.repository.RoleRepository;
//import jakarta.transaction.Transactional;
//import org.springframework.boot.CommandLineRunner;
//import org.springframework.context.annotation.Bean;
//import org.springframework.context.annotation.Configuration;
//
//@Configuration
//public class RoleInitialisation {
//
//    private RoleRepository roleRepository;
//
//    @Bean
//    CommandLineRunner initialiserRoles() {
//        return args -> {
//            System.out.println("Initialisation des rôles");
//        };
//    }
//
//    @Transactional
//    void creerRoles(RoleRepository roleRepository, ERole name) {
//        if (roleRepository.findByName(name).isEmpty()) {
//            Role role = new Role();
//            role.setName(name);
//            roleRepository.save(role);
//        }
//    }
//}
