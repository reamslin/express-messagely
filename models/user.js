/** User class for message.ly */

const db = require("../db");
const ExpressError = require("../expressError");
const bcyrpt = require('bcrypt');
const { BCRYPT_WORK_FACTOR } = require("../config");
/** User of the site. */

class User {

  /** register new user -- returns
   *    {username, password, first_name, last_name, phone}
   */

  static async register({ username, password, first_name, last_name, phone }) {
    console.log(`Trying to hash ${password}`)
    const hashedPassword = await bcyrpt.hash(
      password, BCRYPT_WORK_FACTOR);
    const result = await db.query(`
    INSERT INTO users
    (username, password, first_name, last_name, phone, join_at, last_login_at)
    VALUES ($1, $2, $3, $4, $5, current_timestamp, current_timestamp)
    RETURNING username
    `, [username, hashedPassword, first_name, last_name, phone]);
    if (result.rows[0] === undefined) {
      throw new ExpressError("Could not register user")
    }
    return { username, password: hashedPassword, first_name, last_name, phone }
  };

  /** Authenticate: is this username/password valid? Returns boolean. */

  static async authenticate(username, password) {
    const result = await db.query(
      `SELECT password FROM users 
      WHERE username = $1`,
      [username]
    );
    const user = result.rows[0];

    const okay = await bcyrpt.compare(password, user.password)
    console.log(okay);
    return okay

  }

  /** Update last_login_at for user */

  static async updateLoginTimestamp(username) {
    const result = await db.query(
      `UPDATE users SET last_login_at = current_timestamp
      WHERE username = $1
      RETURNING username`, [username]
    );
    if (!result.rows[0]) {
      throw new ExpressError(`User not found: ${username}`, 404);
    }

    return result.rows[0]

  }

  /** All: basic info on all users:
   * [{username, first_name, last_name, phone}, ...] */

  static async all() {
    const result = await db.query(
      `SELECT username, first_name, last_name, phone FROM users`
    );
    return result.rows;
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
    const result = await db.query(
      `SELECT username, first_name, last_name, phone, join_at, last_login_at
      FROM users
      WHERE username = $1`, [username]
    );
    if (!result.rows[0]) {
      throw new ExpressError(`User not found: ${username}`, 404);
    }

    return result.rows[0];
  }

  /** Return messages from this user.
   *
   * [{id, to_user, body, sent_at, read_at}]
   *
   * where to_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesFrom(username) {
    const result = await db.query(
      `SELECT m.id,
      m.from_username,
      f.first_name AS from_first_name,
      f.last_name AS from_last_name,
      f.phone AS from_phone,
      m.to_username,
      t.first_name AS to_first_name,
      t.last_name AS to_last_name,
      t.phone AS to_phone,
      m.body,
      m.sent_at,
      m.read_at
      FROM messages AS m
      JOIN users AS f ON m.from_username = f.username
      JOIN users AS t ON m.to_username = t.username
      WHERE f.username = $1`, [username]);
    const messages = result.rows.map(r => {
      return {
        id: r.id,
        to_user: {
          username: r.to_username,
          first_name: r.to_first_name,
          last_name: r.to_last_name,
          phone: r.to_phone
        },
        body: r.body,
        sent_at: r.sent_at,
        read_at: r.read_at
      }
    });
    return messages;
  }

  /** Return messages to this user.
   *
   * [{id, from_user, body, sent_at, read_at}]
   *
   * where from_user is
   *   {id, first_name, last_name, phone}
   */

  static async messagesTo(username) {
    const result = await db.query(`
    SELECT m.id,
    m.from_username,
    f.first_name AS from_first_name,
    f.last_name AS from_last_name,
    f.phone AS from_phone,
    m.to_username,
    t.first_name AS to_first_name,
    t.last_name AS to_last_name,
    t.phone AS to_phone,
    m.body,
    m.sent_at,
    m.read_at
    FROM messages AS m
    JOIN users AS f ON m.from_username = f.username
    JOIN users AS t ON m.to_username = t.username
    WHERE t.username = $1`, [username]);
    const messages = result.rows.map(r => {
      return {
        id: r.id,
        from_user: {
          username: r.from_username,
          first_name: r.from_first_name,
          last_name: r.from_last_name,
          phone: r.from_phone
        },
        body: r.body,
        sent_at: r.sent_at,
        read_at: r.read_at
      }
    });
    return messages;
  }
}


module.exports = User;