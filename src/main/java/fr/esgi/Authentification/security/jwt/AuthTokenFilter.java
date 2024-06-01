package fr.esgi.Authentification.security.jwt;

import java.io.IOException;

import com.fasterxml.jackson.databind.ObjectMapper;
import fr.esgi.Authentification.mapper.JwtErrorMapper;
import fr.esgi.Authentification.payload.response.JwtErrorDTO;
import fr.esgi.Authentification.security.service.TokenBlacklist;
import fr.esgi.Authentification.security.service.impl.UtilisateurDetailsServiceImpl;
import fr.esgi.Authentification.exception.SecurityException;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.filter.OncePerRequestFilter;

@Component
public class AuthTokenFilter extends OncePerRequestFilter {
    @Autowired
    private JwtTokenProvider jwtTokenProvider;

    private static final ObjectMapper mapper = new ObjectMapper();

    @Autowired
    private UtilisateurDetailsServiceImpl utilisateurDetailsServiceImpl;

    @Autowired
    private static final JwtErrorMapper mapStruct = JwtErrorMapper.INSTANCE;

    @Autowired
    private TokenBlacklist tokenBlacklist;

    private static final Logger logger = LoggerFactory.getLogger(AuthTokenFilter.class);

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        if ("OPTIONS".equalsIgnoreCase(request.getMethod())) {
            response.setStatus(HttpServletResponse.SC_OK);
            return;
        }

        try {
            String jwt = parseJwt(request);
            if (jwt != null && jwtTokenProvider.validateJwtToken(jwt)) {
                String username = jwtTokenProvider.getUserNameFromJwtToken(jwt);
                UserDetails userDetails = utilisateurDetailsServiceImpl.loadUserByUsername(username);

                // Validate if the token is blacklisted
                if (!tokenBlacklist.isBlacklisted(jwt)) {
                    UsernamePasswordAuthenticationToken authentication = new UsernamePasswordAuthenticationToken(
                            userDetails,
                            null,
                            userDetails.getAuthorities());
                    authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(
                            request));
                    SecurityContextHolder.getContext().setAuthentication(authentication);
                } else {
                    // Token is blacklisted, deny access
                    response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
                    return;
                }
            }
        } catch (final SecurityException exception) {
            JwtErrorDTO jwtErrorDTO = mapStruct.toDto(exception);
            logger.error("Cannot set user authentication: {}", exception.getMessage());
            response.setStatus(exception.getHttpStatus());
            response.setContentType("application/json");
            response.setCharacterEncoding("UTF-8");
            response.getWriter().write(mapper.writeValueAsString(jwtErrorDTO));
            return;
        }

        filterChain.doFilter(request, response);
    }


    private String parseJwt(HttpServletRequest request) {
        String headerAuth = request.getHeader("Authorization");

        if (StringUtils.hasText(headerAuth) && headerAuth.startsWith("Bearer ")) {
            return headerAuth.substring(7, headerAuth.length());
        }

        return null;
    }
}