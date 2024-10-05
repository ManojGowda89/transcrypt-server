const rateLimit = require('express-rate-limit');
const walletRateLimiter = rateLimit({
    windowMs: 5 * 60 * 1000, // 5 minutes window
    max: 20, 
    message: { message: 'Too many requests from this IP, please try again later.' },
    headers: true,
    keyGenerator: (req) => req.ip,
});

const minuteRateLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, // 1 minute window
    max: 5, 
    message: { message: 'Too many requests from this IP, please try again later.' },
    headers: true,
});

module.exports = { walletRateLimiter,minuteRateLimiter  };