# Pending migration

Run `notification_delivery_log.sql` first in a non-production Supabase project. The filename is intentionally not timestamped because this repository was downloaded without Supabase CLI/migration history. When the correct project is connected, create the real migration with `supabase migration new notification_delivery_log`, copy the reviewed SQL into it, and verify with the database advisors.
