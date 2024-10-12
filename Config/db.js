// /Config/db.js
const { Sequelize } = require('sequelize');
const dotenv = require('dotenv');
dotenv.config();

const sequelize = new Sequelize(process.env.SQL_DATABASE, process.env.SQL_USER, process.env.SQL_PASSWORD, {
  host: process.env.SQL_HOST,
  dialect: 'mssql', // Asegúrate de usar el dialecto correcto
  port: process.env.SQL_PORT || 1433,
  logging: false,
  dialectOptions: {
    options: {
      encrypt: true, // Para SQL Server
    },
  },
});

// Probar la conexión
sequelize.authenticate()
  .then(() => console.log('Conexión exitosa a la base de datos SQL Server'))
  .catch(err => console.error('No se pudo conectar a la base de datos:', err));

module.exports = sequelize;
