CREATE TRIGGER audit_retention_after_insert AFTER INSERT ON audit
BEGIN
 DELETE FROM audit WHERE id <= (
  SELECT id FROM audit ORDER BY id DESC LIMIT 1 OFFSET
   COALESCE((SELECT CAST(value AS INTEGER) FROM metadata WHERE key='audit_retention'), 1000)
 );
END;
