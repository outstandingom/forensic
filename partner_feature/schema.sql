-- Schema extensions for the "Become a Partner" feature
-- This assumes you have an existing 'users' or 'profiles' table. 
-- Adjust table names according to your actual schema.

-- 1. Add fields to existing users table (example name: public.users)
-- ALTER TABLE public.users 
-- ADD COLUMN is_partner BOOLEAN DEFAULT false,
-- ADD COLUMN partner_code VARCHAR(50) UNIQUE,
-- ADD COLUMN wallet_balance NUMERIC(10, 2) DEFAULT 0.00;

-- Let's create a dedicated table for demonstration if you prefer separating the logic
CREATE TABLE IF NOT EXISTS public.partner_profiles (
  user_id UUID PRIMARY KEY REFERENCES auth.users(id) ON DELETE CASCADE,
  is_partner BOOLEAN DEFAULT false,
  partner_code VARCHAR(50) UNIQUE,
  wallet_balance NUMERIC(10, 2) DEFAULT 0.00,
  created_at TIMESTAMPTZ DEFAULT now(),
  updated_at TIMESTAMPTZ DEFAULT now()
);

-- 2. Table to track purchases where a coupon was applied
CREATE TABLE IF NOT EXISTS public.partner_purchases (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  buyer_id UUID REFERENCES auth.users(id),
  product_name VARCHAR(255) NOT NULL, -- e.g., 'Website-to-App Converter'
  original_price NUMERIC(10, 2) NOT NULL,
  discount_applied NUMERIC(10, 2) DEFAULT 0.00,
  final_price NUMERIC(10, 2) NOT NULL,
  applied_partner_code VARCHAR(50) REFERENCES public.partner_profiles(partner_code),
  partner_reward_coins NUMERIC(10, 2) DEFAULT 0.00,
  created_at TIMESTAMPTZ DEFAULT now()
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_partner_code ON public.partner_profiles(partner_code);
CREATE INDEX IF NOT EXISTS idx_partner_purchases_buyer ON public.partner_purchases(buyer_id);
CREATE INDEX IF NOT EXISTS idx_partner_purchases_code ON public.partner_purchases(applied_partner_code);

-- 3. Trigger to update updated_at
CREATE OR REPLACE FUNCTION update_modified_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ language 'plpgsql';

CREATE TRIGGER update_partner_profiles_modtime
BEFORE UPDATE ON public.partner_profiles
FOR EACH ROW
EXECUTE FUNCTION update_modified_column();
