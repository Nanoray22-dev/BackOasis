const { Sequelize, DataTypes } = require('sequelize');
const sequelize = require('../Config/db');
const User = require('./User'); // Import User for foreign key relations
const Comment = require('./Comments'); // Import Comment for foreign key relations
const Report = sequelize.define('Report', {
  id: {
    type: DataTypes.INTEGER,
    autoIncrement: true,
    primaryKey: true,
  },
  title: {
    type: DataTypes.STRING(255),
    allowNull: false,
  },
  description: {
    type: DataTypes.TEXT,
    allowNull: false,
  },
  state: {
    type: DataTypes.ENUM('PENDING', 'PROGRESS', 'COMPLETED', 'CLOSED', 'REJECTED'),
    defaultValue: 'PENDING',
  },
  image: {
    type: DataTypes.JSON, // For storing JSON array of image paths
    allowNull: true,
  },
  incidentDate: {
    type: DataTypes.DATE,
    allowNull: false,
  },
  createdAt: {
    type: DataTypes.DATE,
    defaultValue: Sequelize.literal('GETDATE()'),
  },
  updatedAt: {
    type: DataTypes.DATE,
    defaultValue: Sequelize.literal('GETDATE()'),
  },
}, {
  timestamps: true,
});

module.exports = Report;
