/**
 * express Router middleware for authentication API's admin operations
 *
 * @author Hyecheol (Jerry) Jang <hyecheol123@gmail.com>
 */

import * as express from 'express';
import AuthToken from '../datatypes/AuthToken';
import {NewPassword, validateNewPassword} from '../datatypes/NewPassword';
import AuthenticationError from '../exceptions/AuthenticationError';
import BadRequestError from '../exceptions/BadRequestError';
import User from '../datatypes/User';
import Session from '../datatypes/Session';
import passwordRule from '../utils/passwordRule';
import usernameRule from '../utils/usernameRule';

const adminRouter = express.Router();

// POST /admin/user: Create new user
adminRouter.post(
  '/user',
  async (
    req: express.Request,
    res: express.Response,
    next: express.NextFunction
  ) => {
    try {
      // Verify admin's access token
      const content: AuthToken = req.app.locals.accessTokenVerify(req);
      if (content.admin !== true) {
        throw new AuthenticationError();
      }

      const input: User = req.body;
      if (
        !User.validateNewUserForm(input) || // Verify admin's input
        !usernameRule(input.username) || // Check Username and Password Rule
        !passwordRule(input.username, input.password)
      ) {
        throw new BadRequestError();
      }

      // Create newUser
      const membersince = new Date(input.membersince);
      membersince.setMilliseconds(0);
      // Hash Password
      const hashedPassword = req.app.locals.hash(
        input.username,
        membersince.toISOString(),
        input.password
      );
      if (input.admin !== true) {
        input.admin = false;
      }
      const newUser = new User(
        membersince,
        hashedPassword,
        input.username,
        input.admin
      );

      // Write to DB
      await User.create(req.app.locals.dbClient, newUser);

      // Response
      res.status(201).send();
    } catch (e) {
      next(e);
    }
  }
);

// DELETE /admin/user/{username}: Delete an existing user
adminRouter.delete(
  '/user/:username',
  async (
    req: express.Request,
    res: express.Response,
    next: express.NextFunction
  ) => {
    try {
      // Verify admin's access token
      const content: AuthToken = req.app.locals.accessTokenVerify(req);
      if (content.admin !== true) {
        throw new AuthenticationError();
      }

      // Verify username
      const delTarget = req.params.username; // username that will be deleted
      if (!usernameRule(delTarget)) {
        throw new BadRequestError();
      }

      await Promise.all([
        // Delete User
        User.delete(req.app.locals.dbClient, delTarget),
        // Delete Sessions
        Session.deleteAll(req.app.locals.dbClient, delTarget),
      ]);

      // response
      res.status(200).send();
    } catch (e) {
      next(e);
    }
  }
);

// PUT /user/{username}/password: Reset User's password
adminRouter.put(
  '/user/:username/password',
  async (
    req: express.Request,
    res: express.Response,
    next: express.NextFunction
  ) => {
    try {
      // Verify Admin's Access Token
      const content: AuthToken = req.app.locals.accessTokenVerify(req);
      if (content.admin !== true) {
        throw new AuthenticationError();
      }

      // Verify User's Input
      const editTarget = req.params.username;
      const input: NewPassword = req.body;
      if (!validateNewPassword(input) || !usernameRule(editTarget)) {
        throw new BadRequestError();
      }
      const newPassword: string = input.newPassword;

      // Retrieve User Information from DB
      const user = await User.read(req.app.locals.dbClient, editTarget);

      // Check password Rule
      if (!passwordRule(user.username, newPassword)) {
        throw new BadRequestError();
      }

      // Hash Password
      const hashedPassword = req.app.locals.hash(
        user.username,
        (user.membersince as Date).toISOString(),
        newPassword
      );

      // Write to DB + Logout From all currently signed in session
      await Promise.all([
        User.updatePassword(
          req.app.locals.dbClient,
          user.username,
          hashedPassword
        ),
        Session.deleteAll(req.app.locals.dbClient, user.username),
      ]);

      // Response
      res.status(200).send();
    } catch (e) {
      next(e);
    }
  }
);

export default adminRouter;
