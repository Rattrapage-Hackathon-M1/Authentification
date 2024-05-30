package fr.esgi.Authentification.mapper;

import fr.esgi.Authentification.payload.response.JwtErrorDTO;
import fr.esgi.Authentification.exception.SecurityException;
import org.mapstruct.Mapping;
import org.mapstruct.factory.Mappers;
import org.mapstruct.Mapper;


@Mapper(componentModel = "spring")
public interface JwtErrorMapper {
    public JwtErrorMapper INSTANCE = Mappers.getMapper(JwtErrorMapper.class);

    @Mapping(target = "status", source = "httpStatus")
    JwtErrorDTO toDto(SecurityException e);
}
