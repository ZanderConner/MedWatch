#!/usr/bin/env bash
set -euo pipefail

host="${OPENEMR_DB_HOST:-openemr-db}"
database="${OPENEMR_DB_NAME:-openemr}"
user="${OPENEMR_DB_USER:-root}"

for _ in $(seq 1 90); do
  if mariadb -h "$host" -u "$user" -e "SELECT 1" >/dev/null 2>&1; then
    break
  fi
  sleep 2
done

# Order matters: providers must exist before patients.sql can link
# providerID, and patients must exist before appointments.sql can
# schedule visits for them.
mariadb -h "$host" -u "$user" "$database" < /seed/providers.sql
echo "OpenEMR provider seed complete"

mariadb -h "$host" -u "$user" "$database" < /seed/patients.sql
echo "OpenEMR patient seed complete"

mariadb -h "$host" -u "$user" "$database" < /seed/appointments.sql
echo "OpenEMR appointment seed complete"
