/**
 * Express application middleware dealing with the API requests
 *
 * @author Hyecheol (Jerry) Jang <hyecheol123@gmail.com>
 */

import * as express from 'express';
import * as mariadb from 'mariadb';
import * as jwt from 'jsonwebtoken';
import * as cookieParser from 'cookie-parser';
import * as pinoHttp from 'pino-http';
import * as pino from 'pino';
import ServerConfig from './ServerConfig';
import AuthenticationError from './exceptions/AuthenticationError';
import HTTPError from './exceptions/HTTPError';
import AuthToken from './datatypes/AuthToken';
import adminRouter from './routes/admin';
import aliveRouter from './routes/alive';
import authRouter from './routes/auth';
import Session from './datatypes/Session';
import RefreshTokenVerifyResult from './datatypes/RefreshTokenVerifyResult';
import JWTObject from './datatypes/JWTObject';

/**
 * Class contains Express Application and other relevant instances/functions
 */
export default class ExpressServer {
  app: express.Application;
  logger: pino.Logger;

  /**
   * Constructor for ExpressAppHelper
   *
   * @param config Server's configuration
   */
  constructor(config: ServerConfig) {
    // Setup Express Application
    this.app = express(); // initialize express application
    this.app.locals.dbClient = mariadb.createPool({
      // Create db connection pool and link to the express application
      host: config.dbURL,
      port: config.dbPort,
      user: config.dbUsername,
      password: config.dbPassword,
      database: config.defaultDatabase,
      compress: true,
    });

    // link password hash function to the express application
    this.app.locals.hash = config.hash;

    // JWT Keys
    this.app.set('jwtAccessKey', config.jwtSecretKey);
    this.app.set('jwtRefreshKey', config.jwtRefreshKey);

    // link functions to verify JWT Tokens
    // function to verify access token, return username
    this.app.locals.accessTokenVerify = (req: express.Request): AuthToken => {
      if (!('X-ACCESS-TOKEN' in req.cookies)) {
        throw new AuthenticationError();
      }
      let tokenContents: AuthToken; // place to store contents of JWT
      // Verify and retrieve the token contents
      try {
        tokenContents = jwt.verify(
          req.cookies['X-ACCESS-TOKEN'],
          config.jwtSecretKey,
          {algorithms: ['HS512']}
        ) as AuthToken;
      } catch (e) {
        throw new AuthenticationError();
      }
      if (tokenContents.type !== 'access') {
        throw new AuthenticationError();
      }
      delete (tokenContents as JWTObject).iat;
      delete (tokenContents as JWTObject).exp;
      return tokenContents;
    };
    // function to verify refresh token, return username
    this.app.locals.refreshTokenVerify = async (
      req: express.Request
    ): Promise<RefreshTokenVerifyResult> => {
      if (!('X-REFRESH-TOKEN' in req.cookies)) {
        // No token provided
        throw new AuthenticationError();
      }

      let tokenContents: AuthToken; // place to store contents of JWT
      // Verify and retrieve the token contents
      try {
        tokenContents = jwt.verify(
          req.cookies['X-REFRESH-TOKEN'],
          config.jwtRefreshKey,
          {algorithms: ['HS512']}
        ) as AuthToken;
      } catch (e) {
        throw new AuthenticationError();
      }
      if (tokenContents.type !== 'refresh') {
        throw new AuthenticationError();
      }

      // Check Token in the Database
      const dbResult = await Session.read(
        this.app.locals.dbClient,
        req.cookies['X-REFRESH-TOKEN']
      );
      if (dbResult.length !== 1 || dbResult[0].expires < new Date()) {
        throw new AuthenticationError();
      }

      // If RefreshToken Expires within 20min, need to renew it
      const expectedExpire = new Date();
      expectedExpire.setMinutes(new Date().getMinutes() + 20);
      delete (tokenContents as JWTObject).iat;
      delete (tokenContents as JWTObject).exp;
      if (dbResult[0].expires < expectedExpire) {
        // Less than 20min left
        return {content: tokenContents, needRenew: true};
      } else {
        return {content: tokenContents, needRenew: false};
      }
    };

    // Setup Parsers
    this.app.use(express.json());
    this.app.use(cookieParser());

    // Setup Logger
    const pinoOptions: pino.LoggerOptions = {
      name: 'MakeBSSGreatAgain-Auth-API',
      formatters: {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        log(object: any) {
          object.username = object.res.req.username;
          return object;
        },
        bindings(bindings) {
          return {hostname: bindings.hostname};
        },
      },
      redact: {
        paths: [
          'req.id',
          'req.headers.connection',
          'req.headers.cookie',
          'res.headers["set-cookie"]',
          'res.headers.etag',
          'res.headers["x-powered-by"]',
          'res.headers.charset',
          'msg',
        ],
        remove: true,
      },
    };
    // Logging to stdout
    const logger = pino(
      pinoOptions,
      pino.destination({sync: false, minLength: 4096})
    );
    this.app.use(pinoHttp({logger: logger}));
    // Flush Log every 15 seconds when idle
    /* istanbul ignore next */
    setInterval(() => {
      logger.flush();
    }, 15000).unref();
    this.logger = logger;

    // Only Allow GET, POST, DELETE, PUT method
    this.app.use(
      (
        req: express.Request,
        _res: express.Response,
        next: express.NextFunction
      ): void => {
        // Test for HTTP methods
        if (!['GET', 'POST', 'DELETE', 'PUT', 'HEAD'].includes(req.method)) {
          next(new HTTPError(405, 'Method Not Allowed'));
        } else {
          // When the request is valid, handle the request properly
          next();
        }
      }
    );

    // Add List of Routers
    this.app.use('/', authRouter);
    this.app.use('/admin', adminRouter);
    this.app.use('/alive', aliveRouter);

    // Default Error Handler
    this.app.use(
      (
        err: HTTPError | Error,
        _req: express.Request,
        res: express.Response,
        // eslint-disable-next-line @typescript-eslint/no-unused-vars
        _next: express.NextFunction
      ): void => {
        /* istanbul ignore next */
        if (!(err instanceof HTTPError)) {
          console.error(err);
          err = new HTTPError(500, 'Server Error');
        }
        res.status((err as HTTPError).statusCode).json({error: err.message});
      }
    );
  }

  /**
   * CLose Server
   * - Close connection with Database server gracefully
   * - Flush Log
   */
  async closeServer(): Promise<void> {
    await Promise.all([this.app.locals.dbClient.end(), this.logger.flush()]);
  }
}
