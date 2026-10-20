-- Demo data. The first user (admin) is what a login-bypass injection logs in
-- as, and the users table is the prize the advanced SQL-injection chain dumps.

INSERT INTO users (username, password, full_name, email, account_number, balance) VALUES
  ('admin',  'Sup3rSecret!2026', 'Aisha Admin',   'admin@securebank.test',  '10000001', 250000.00),
  ('ali',    'ali-banking-pw',   'Ali Naqi',      'ali@securebank.test',    '10000002',  48230.75),
  ('ayesha', 'ayesha-pw-2026',   'Ayesha Noor',   'ayesha@securebank.test', '10000003',  51200.00),
  ('fatima', 'fatima!secure',    'Fatima Khan',   'fatima@securebank.test', '10000004',  12750.50);

-- Transactions for admin (id=1) and ali (id=2) so the search page has content.
INSERT INTO transactions (user_id, description, amount) VALUES
  (1, 'Opening deposit',          250000.00),
  (1, 'Grocery store purchase',     -84.20),
  (1, 'Salary credit',            180000.00),
  (1, 'Electricity bill',          -220.00),
  (2, 'Opening deposit',           50000.00),
  (2, 'Grocery store purchase',     -64.90),
  (2, 'Online shopping - books',   -129.99),
  (2, 'ATM withdrawal',            -500.00),
  (2, 'Mobile top-up',              -20.00);

INSERT INTO messages (user_id, body) VALUES
  (1, 'Remember to review the quarterly audit.'),
  (2, 'Call the bank about the new debit card.');
