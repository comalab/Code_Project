CREATE TABLE courses (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  badge TEXT NOT NULL,
  title TEXT NOT NULL,
  category TEXT NOT NULL,
  satisfaction TEXT,
  start_date TEXT NOT NULL,
  end_date TEXT NOT NULL,
  capacity INTEGER,
  applied INTEGER,
  price_original INTEGER NOT NULL,
  price_tiers TEXT NOT NULL,
  work24_url TEXT NOT NULL,
  image_key TEXT,
  featured INTEGER NOT NULL DEFAULT 0,
  sort_order INTEGER NOT NULL DEFAULT 0,
  created_at TEXT DEFAULT (datetime('now')),
  updated_at TEXT DEFAULT (datetime('now'))
);
