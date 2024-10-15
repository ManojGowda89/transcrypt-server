const rateLimit = require('express-rate-limit');

// Rate limiter for minute-based requests
const minuteRateLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute window
    max: 5, 
    message: { message: 'Too many requests from this IP, please try again later.' },
    headers: true,
});

module.exports = { minuteRateLimiter };
