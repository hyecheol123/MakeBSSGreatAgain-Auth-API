/**
 * Define type and CRUD Methods for each session entry in the database
 *
 * @author Hyecheol (Jerry) Jang <hyecheol123@gmail.com>
 */

import * as mariadb from 'mariadb';

/**
 * Class for each Session
 */
export default class Session {
  readonly token: string; // RefreshToken
  expires: Date; // In DB, format: datetime string
  readonly username: string;

  constructor(token: string, expires: Date, username: string) {
    this.token = token;
    this.expires = expires;
    this.username = username;
  }

  /**
   * Create a session entry in the DB
   *
   * @param dbClient DB Connection Pool
   * @param session Session Information
   */
  static async create(dbClient: mariadb.Pool, session: Session): Promise<void> {
    await dbClient.query(
      'INSERT INTO session (token, expires, username) values (?, ?, ?)',
      [session.token, session.expires, session.username]
    );
  }

  /**
   * Delete current session from database
   *
   * @param dbClient DB Connection Pool
   * @param token refreshToken associated with the Session
   */
  static async delete(dbClient: mariadb.Pool, token: string): Promise<void> {
    await dbClient.query('DELETE FROM session WHERE token = ?', token);
  }

  /**
   * Delete sessions associated with the username, but leave current session
   *
   * @param dbClient DB Connection Pool
   * @param currentToken refreshToken associated with the current Session
   * @param username used to find Session associated with the username
   */
  static async deleteNotCurrent(
    dbClient: mariadb.Pool,
    currentToken: string,
    username: string
  ): Promise<void> {
    await dbClient.query(
      'DELETE FROM session WHERE username = ? AND (NOT token = ?)',
      [username, currentToken]
    );
  }

  /**
   * Delete sessions associated with the username
   *
   * @param dbClient DB Connection Pool
   * @param username used to find Sessions associated with the username
   */
  static async deleteAll(
    dbClient: mariadb.Pool,
    username: string
  ): Promise<void> {
    await dbClient.query('DELETE FROM session WHERE username = ?', username);
  }

  /**
   * Delete expired Sessions associated with the username
   *
   * @param dbClient DB Connection Pool
   * @param username used to find Sessions associated with the username
   * @param currentDate Date object indicates current date and time
   */
  static async deleteExpired(
    dbClient: mariadb.Pool,
    username: string,
    currentDate: Date
  ): Promise<void> {
    await dbClient.query(
      'DELETE FROM session where username = ? AND expires < ?',
      [username, currentDate]
    );
  }

  /**
   * Retrieve Session with given token
   *
   * @param dbClient DB Connection Pool
   * @param token refreshToken associated with the Session
   * @return Promise of Session Array
   */
  static async read(dbClient: mariadb.Pool, token: string): Promise<Session[]> {
    const queryResult = await dbClient.query(
      'SELECT * FROM session WHERE token = ?',
      token
    );
    for (const entry of queryResult) {
      (entry as Session).expires = new Date(entry.expires);
    }
    return queryResult;
  }
}
