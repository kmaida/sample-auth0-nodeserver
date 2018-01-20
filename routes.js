// Dependencies
const jwt = require('express-jwt');
const jwks = require('jwks-rsa');
// Config
const config = require('./config');
// Data
const dinosaurs = require('./dinosaurs.json');
const dragons = require('./dragons.json');

module.exports = function(app) {
  // Auth0 athentication middleware
  const jwtCheck = jwt({
    secret: jwks.expressJwtSecret({
      cache: true,
      rateLimit: true,
      jwksRequestsPerMinute: 5,
      jwksUri: `https://${config.domain}/.well-known/jwks.json`
    }),
    audience: config.audience,
    issuer: `https://${config.domain}/`,
    algorithm: 'RS256'
  });

  // Check for an authenticated admin user
  const adminCheck = (req, res, next) => {
    const roles = req.user[config.namespace] || [];
    if (roles.indexOf('admin') > -1) {
      next();
    } else {
      res.status(401).send({message: 'Not authorized for admin access'});
    }
  }

  // API works (public)
  app.get('/api', (req, res) => {
    res.send('API works!');
  });

  // GET protected dinosaurs data
  app.get('/api/dinosaurs', jwtCheck, (req, res) => {
    res.send(dinosaurs);
  });

  // GET protected dragons data, accessible only to admins
  app.get('/api/dragons', jwtCheck, adminCheck, (req, res) => {
    res.send(dragons);
  });
};
