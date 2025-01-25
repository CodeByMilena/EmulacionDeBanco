CREATE DATABASE IF NOT EXISTS banco;

USE banco;

CREATE TABLE usuarios (
    id INT AUTO_INCREMENT PRIMARY KEY,
    nombre VARCHAR(100) NOT NULL,
    email VARCHAR(100) NOT NULL UNIQUE,
    contraseña VARCHAR(255) NOT NULL
);

CREATE TABLE transacciones (
    id INT AUTO_INCREMENT PRIMARY KEY,
    origen INT,
    destinatario INT,
    monto DECIMAL(10, 2) NOT NULL,
    fecha DATETIME DEFAULT CURRENT_TIMESTAMP,
    tipo ENUM('pago', 'ingreso') NOT NULL,
    FOREIGN KEY (origen) REFERENCES usuarios(id),
    FOREIGN KEY (destinatario) REFERENCES usuarios(id)
);

CREATE TABLE prestamos (
    id INT AUTO_INCREMENT PRIMARY KEY,
    monto DECIMAL(10, 2) NOT NULL,
    deudor INT,
    FOREIGN KEY (deudor) REFERENCES usuarios(id)
);

CREATE TABLE ctaBancaria (
    nroCuenta INT AUTO_INCREMENT PRIMARY KEY,
    usuario_id INT,
    saldos DECIMAL(10, 2) NOT NULL DEFAULT 0.00,
    cbu CHAR(22) NOT NULL UNIQUE,
    alias VARCHAR(50),
    FOREIGN KEY (usuario_id) REFERENCES usuarios(id) ON DELETE CASCADE
);
