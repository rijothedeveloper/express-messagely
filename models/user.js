/** User class for message.ly */



/** User of the site. */
const bcrypt = require("bcrypt")
const {BCRYPT_WORK_FACTOR} = require("../config")
const db = require("../db");
const ExpressError = require("../expressError");

class User {
  /** register new user -- returns
   *    {username, password, first_name, last_name, phone}
   */

  static async register({ username, password, first_name, last_name, phone }) {
    const hashedPassword = await bcrypt.hash(password, BCRYPT_WORK_FACTOR);
    const results = await db.query(
      `INSERT INTO users 
      (username, password, first_name, last_name, phone, join_at, last_login_at)
      values($1, $2, $3, $4, $5, current_timestamp, current_timestamp) returning username, password, first_name, last_name, phone`,
      [username, hashedPassword, first_name, last_name, phone]
    );

    return results.rows[0];
  }

  /** Authenticate: is this username/password valid? Returns boolean. */

  static async authenticate(username, password) {
    const results = await db.query(
      `select password from users WHERE username = $1`,
      [username]
    );
    const userPass = results.rows[0].password;
    return await bcrypt.compare(password, userPass);
  }

  /** Update last_login_at for user */

  static async updateLoginTimestamp(username) {
    const results = await db.query(
      `UPDATE users SET last_login_at = current_timestamp WHERE username = $1 returning last_login_at`,
      [username]
    );

    if (!results.rows[0]) {
      throw new ExpressError("wrong username", 401);
    }
  }

  /** All: basic info on all users:
   * [{username, first_name, last_name, phone}, ...] */

  static async all() {
    const results = await db.query(
      `SELECT username, first_name, last_name, phone FROM users`
    );
    return results.rows;
  }

  /** Get: get user by username
   *
   * returns {username,
   *          first_name,
   *          last_name,
   *          phone,
   *          join_at,
   *          last_login_at } */

  static async get(username) {
    const results = await db.query(
      `SELECT username, first_name, last_name, phone, join_at, last_login_at FROM users WHERE username = $1`,
      [username]
    );
    return results.rows[0];
  }

  /** Return messages from this user.
   *
   * [{id, to_user, body, sent_at, read_at}]
   *
   * where to_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesFrom(username) {
    const results = await db.query(
      ` SELECT m.id, m.to_username,
      u.first_name,
      u.last_name,
      u.phone,
      m.body,
      m.sent_at,
      m.read_at FROM messages AS m
      JOIN users AS u on m.to_username=u.username
          WHERE from_username = $1`,
      [username]
    );
    return results.rows.map((m) => ({
      id: m.id,
      body: m.body,
      sent_at: m.sent_at,
      read_at: m.read_at,
      to_user: {
        username: m.to_username,
        first_name: m.first_name,
        last_name: m.last_name,
        phone: m.phone,
      },
    }));
  }

  /** Return messages to this user.
   *
   * [{id, from_user, body, sent_at, read_at}]
   *
   * where from_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesTo(username) {
    const results = await db.query(
      ` SELECT m.id, m.from_username,
      u.first_name,
      u.last_name,
      u.phone,
      m.body,
      m.sent_at,
      m.read_at FROM messages AS m
      JOIN users AS u on m.from_username=u.username
          WHERE to_username = $1`,
      [username]
    );
    return results.rows.map((m) => ({
      id: m.id,
      body: m.body,
      sent_at: m.sent_at,
      read_at: m.read_at,
      from_user: {
        username: m.from_username,
        first_name: m.first_name,
        last_name: m.last_name,
        phone: m.phone,
      },
    }));
  }
}


module.exports = User;