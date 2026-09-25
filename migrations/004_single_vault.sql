-- Enforce the product rule: only one vault may exist at a time.
CREATE TRIGGER IF NOT EXISTS prevent_multiple_vaults
BEFORE INSERT ON vaults
WHEN EXISTS (SELECT 1 FROM vaults)
BEGIN
  SELECT RAISE(ABORT, 'Only one vault is allowed');
END;
