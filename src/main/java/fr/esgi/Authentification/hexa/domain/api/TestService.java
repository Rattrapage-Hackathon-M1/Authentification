package fr.esgi.Authentification.hexa.domain.api;


import fr.esgi.Authentification.hexa.domain.Test;
import fr.esgi.Authentification.hexa.domain.spi.IDao;

public class TestService implements IService{

    private final IDao dao;

    public TestService(IDao dao) {
        this.dao = dao;
    }

    @Override
    public Test add(Test newTest) {
        return dao.add(newTest);
    }
}
