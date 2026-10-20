// Database connection pool.
//
// We use mysql2's *non*-prepared query() in the vulnerable code paths on
// purpose, because that is what lets string-concatenated SQL injection work.
// The safe code paths use execute() with bound parameters (? placeholders),
// which sends the SQL and the data separately so user input can never change
// the structure of the query.
const mysql = require("mysql2/promise");

const pool = mysql.createPool({
  host: process.env.DB_HOST || "db",
  user: process.env.DB_USER || "bankuser",
  password: process.env.DB_PASSWORD || "bankpass",
  database: process.env.DB_NAME || "securebank",
  waitForConnections: true,
  connectionLimit: 10,
  // multipleStatements stays OFF: it is not needed for any of our injections
  // and leaving it on would hide how dangerous a single-statement injection is.
  multipleStatements: false,
});

module.exports = pool;
