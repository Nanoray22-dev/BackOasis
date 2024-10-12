const User = require('./User');
const Comment = require('./Comments');
const Report = require('./Report');

// Define relationships here
Report.belongsTo(User, { foreignKey: 'createdBy', as: 'creator' });
Report.belongsTo(User, { foreignKey: 'assignedTo', as: 'assignee' });
Report.hasMany(Comment, { as: 'comments', foreignKey: 'reportId' });

Comment.belongsTo(User, { foreignKey: 'createdBy', as: 'creator' });
Comment.belongsTo(Report, { foreignKey: 'reportId', as: 'report' });

module.exports = { Report, Comment };
