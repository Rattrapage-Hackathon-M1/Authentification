DO
'
DECLARE
BEGIN
    IF NOT EXISTS (SELECT 1 FROM roles WHERE name = ''ROLE_EMPLOYE'') THEN
        INSERT INTO roles(name) VALUES (''ROLE_EMPLOYE'');
    END IF;

    IF NOT EXISTS (SELECT 1 FROM roles WHERE name = ''ROLE_MANAGER'') THEN
        INSERT INTO roles(name) VALUES (''ROLE_MANAGER'');
    END IF;

    IF NOT EXISTS (SELECT 1 FROM roles WHERE name = ''ROLE_ADMIN'') THEN
        INSERT INTO roles(name) VALUES (''ROLE_ADMIN'');
    END IF;
END;
'  LANGUAGE PLPGSQL;