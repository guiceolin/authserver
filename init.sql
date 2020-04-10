CREATE DATABASE authserver;

CREATE USER authserver WITH PASSWORD 'authserver';

GRANT ALL PRIVILEGES ON DATABASE authserver TO authserver;
