-- Migration 036: Populate profiles for existing customer_vendors
--
-- This migration creates third_party_profiles for existing customer_vendors
-- that don't have a profile yet.

DO $$
DECLARE
    cv_record RECORD;
    profile_id INTEGER;
BEGIN
    -- Loop through customer_vendors without profiles
    FOR cv_record IN 
        SELECT cv.id, cv.customer_id, cv.vendor_id, cv.vendor, 
               cv.criticality, cv.data_sensitivity, cv.relationship_type
        FROM customer_vendors cv
        LEFT JOIN third_party_profiles tp ON tp.customer_vendor_id = cv.id
        WHERE tp.id IS NULL
    LOOP
        -- Create a profile for each customer_vendor
        INSERT INTO third_party_profiles (
            customer_vendor_id,
            business_role,
            data_access_level,
            privileged_access,
            criticality,
            risk_score
        ) VALUES (
            cv_record.id,
            cv_record.relationship_type,
            cv_record.data_sensitivity,
            FALSE,
            COALESCE(cv_record.criticality, 'MEDIUM'),
            0
        )
        RETURNING id INTO profile_id;
        
        RAISE NOTICE 'Created profile % for customer_vendor % (vendor: %)', 
                     profile_id, cv_record.id, cv_record.vendor;
    END LOOP;
END $$;
