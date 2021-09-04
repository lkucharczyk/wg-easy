'use strict';

const fs = require('fs');
const path = require('path');

const express = require('express');
const expressSession = require('express-session');
const debug = require('debug')('Server');

const Util = require('./Util');
const ServerError = require('./ServerError');
const WireGuard = require('../services/WireGuard');

const {
  PORT,
  RELEASE,
  PASSWORD,
  BASEPATH,
} = require('../config');

module.exports = class Server {

  constructor() {
    const indexReady = fs.promises.readFile(
      path.join(__dirname, '..', 'www', 'index.template.html'),
      { encoding: 'utf8' }
    ).then(async f => {
      return fs.promises.writeFile(
        path.join(__dirname, '..', 'www', 'index.html'),
        f.replace(/<!--BASEPATH-->/g, BASEPATH)
      );
    });

    // Express
    this.app = express()
      .disable('etag')
      .get(BASEPATH + '/index.template.html', (_req, res) => { res.status(404).end() } )
      .use(BASEPATH + '/', express.static(path.join(__dirname, '..', 'www')))
      .use(express.json())
      .use(expressSession({
        secret: String(Math.random()),
        resave: true,
        saveUninitialized: true,
        cookie: {
          path: BASEPATH || '/'
        }
      }))

      .get(BASEPATH + '/api/release', (Util.promisify(async () => {
        return RELEASE;
      })))

      // Authentication
      .get(BASEPATH + '/api/session', Util.promisify(async req => {
        const requiresPassword = !!process.env.PASSWORD;
        const authenticated = requiresPassword
          ? !!(req.session && req.session.authenticated)
          : true;

        return {
          requiresPassword,
          authenticated,
        };
      }))
      .post(BASEPATH + '/api/session', Util.promisify(async req => {
        const {
          password,
        } = req.body;

        if (typeof password !== 'string') {
          throw new ServerError('Missing: Password', 401);
        }

        if (password !== PASSWORD) {
          throw new ServerError('Incorrect Password', 401);
        }

        req.session.authenticated = true;
        req.session.save();

        debug(`New Session: ${req.session.id})`);
      }))

      // WireGuard
      .use((req, res, next) => {
        if (!PASSWORD) {
          return next();
        }

        if (req.session && req.session.authenticated) {
          return next();
        }

        return res.status(401).json({
          error: 'Not Logged In',
        });
      })
      .delete(BASEPATH + '/api/session', Util.promisify(async req => {
        const sessionId = req.session.id;

        req.session.destroy();

        debug(`Deleted Session: ${sessionId}`);
      }))
      .get(BASEPATH + '/api/wireguard/client', Util.promisify(async req => {
        return WireGuard.getClients();
      }))
      .get(BASEPATH + '/api/wireguard/client/:clientId/qrcode.svg', Util.promisify(async (req, res) => {
        const { clientId } = req.params;
        const svg = await WireGuard.getClientQRCodeSVG({ clientId });
        res.header('Content-Type', 'image/svg+xml');
        res.send(svg);
      }))
      .get(BASEPATH + '/api/wireguard/client/:clientId/configuration', Util.promisify(async (req, res) => {
        const { clientId } = req.params;
        const client = await WireGuard.getClient({ clientId });
        const config = await WireGuard.getClientConfiguration({ clientId });
        res.header('Content-Disposition', `attachment; filename="${client.name}.conf"`);
        res.header('Content-Type', 'text/plain');
        res.send(config);
      }))
      .post(BASEPATH + '/api/wireguard/client', Util.promisify(async req => {
        const { name } = req.body;
        return WireGuard.createClient({ name });
      }))
      .delete(BASEPATH + '/api/wireguard/client/:clientId', Util.promisify(async req => {
        const { clientId } = req.params;
        return WireGuard.deleteClient({ clientId });
      }))
      .post(BASEPATH + '/api/wireguard/client/:clientId/enable', Util.promisify(async req => {
        const { clientId } = req.params;
        return WireGuard.enableClient({ clientId });
      }))
      .post(BASEPATH + '/api/wireguard/client/:clientId/disable', Util.promisify(async req => {
        const { clientId } = req.params;
        return WireGuard.disableClient({ clientId });
      }))
      .put(BASEPATH + '/api/wireguard/client/:clientId/name', Util.promisify(async req => {
        const { clientId } = req.params;
        const { name } = req.body;
        return WireGuard.updateClientName({ clientId, name });
      }))
      .put(BASEPATH + '/api/wireguard/client/:clientId/address', Util.promisify(async req => {
        const { clientId } = req.params;
        const { address } = req.body;
        return WireGuard.updateClientAddress({ clientId, address });
      }));

    indexReady.then(() => {
      this.app.listen(PORT, () => {
        debug(`Listening on http://0.0.0.0:${PORT}${BASEPATH}`);
      });
    });
  }

};
