const winston = require('winston');
require('winston-daily-rotate-file');
const path = require('path');

const logDir = 'logs'; // Ensure this directory exists or create it dynamically

// Common format for both console and file
const unifiedFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.printf(info => {
    return `${info.timestamp} [${info.level}]: ${info.message}`;
  })
);

// Configuration for daily rotation of log files
const dailyRotateFileTransport = new winston.transports.DailyRotateFile({
  filename: path.join(logDir, '%DATE%.log'),
  datePattern: 'YYYY-MM-DD',
  zippedArchive: true,
  maxFiles: '21d',
  auditFile: path.join(logDir, '.audit.json'),
  level: 'info',
  format: unifiedFormat // Use the same format for file logs
});

// Create the logger instance with both console and file transports using the same format
const logger = winston.createLogger({
  transports: [
    new winston.transports.Console({
      format: unifiedFormat // Apply the same format to console
    }),
    dailyRotateFileTransport
  ]
});

module.exports = logger;
