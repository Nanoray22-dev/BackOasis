const { Sequelize, DataTypes } = require('sequelize');
const sequelize = require('../Config/db');
const User = require('./User');

const Message = sequelize.define('Message', {
  id: {
    type: DataTypes.INTEGER,
    autoIncrement: true,
    primaryKey: true,
  },
  text: {
    type: DataTypes.STRING(255),
    allowNull: true,
  },
  fileName: {
    type: DataTypes.STRING(255),
    allowNull: true,  // Path to the file, if any
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

// Relationships
Message.belongsTo(User, { foreignKey: 'senderId', as: 'sender' });
Message.belongsTo(User, { foreignKey: 'recipientId', as: 'recipient' });

module.exports = Message;
