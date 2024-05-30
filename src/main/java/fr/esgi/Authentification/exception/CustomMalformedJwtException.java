package fr.esgi.Authentification.exception;

public class CustomMalformedJwtException extends CustomTechnicalJwtException {
    public CustomMalformedJwtException() {
        super("Token mal formatté");
    }
}
