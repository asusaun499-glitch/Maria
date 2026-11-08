-- Run once in TiDB Cloud SQL Editor, selecting the maria_music database.
ALTER TABLE songs
  ADD COLUMN category VARCHAR(100) NOT NULL DEFAULT 'เพลงของ Maria';
