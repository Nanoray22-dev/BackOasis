const { Sequelize, DataTypes } = require('sequelize');
const sequelize = require('../Config/db');

const User = sequelize.define('User', {
  id: {
    type: DataTypes.INTEGER,
    autoIncrement: true,
    primaryKey: true,
  },
  username: {
    type: DataTypes.STRING(255),
    allowNull: false,
    unique: true,
  },
  password: {
    type: DataTypes.STRING(255),
    allowNull: false,
  },
  email: {
    type: DataTypes.STRING(255),
    allowNull: true,
  },
  address: {
    type: DataTypes.STRING(255),
    allowNull: true,
  },
  phone: {
    type: DataTypes.STRING(50),
    allowNull: true,
  },
  age: {
    type: DataTypes.INTEGER,
    allowNull: true,
  },
  residenceType: {
    type: DataTypes.ENUM('apartamento', 'casa', 'duplex', 'no residente'),
    allowNull: false,
    defaultValue: 'apartamento',
  },
  role: {
    type: DataTypes.ENUM('admin', 'usuario'),
    defaultValue: 'usuario',
  },
  profileImage: {
    type: DataTypes.BLOB('long'), // For VARBINARY(MAX) in SQL Server
    allowNull: true,
  },
  createdAt: {
    type: DataTypes.DATE,
    defaultValue: Sequelize.literal('GETDATE()'), // SQL Server date
  },
  updatedAt: {
    type: DataTypes.DATE,
    defaultValue: Sequelize.literal('GETDATE()'),
  },
}, {
  timestamps: true,  // Automatically sets createdAt/updatedAt fields
});

module.exports = User;
