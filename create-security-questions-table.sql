-- Create SecurityQuestion table manually
-- Run this script in your PostgreSQL database

-- Check if table exists first
DO $$ 
BEGIN
    IF NOT EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'security_questions') THEN
        CREATE TABLE security_questions (
            user_id VARCHAR NOT NULL,
            question VARCHAR NOT NULL,
            answer_hash VARCHAR NOT NULL,
            is_changed BOOLEAN NOT NULL DEFAULT FALSE,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            
            -- Add foreign key constraint
            CONSTRAINT fk_security_questions_user_id 
                FOREIGN KEY (user_id) 
                REFERENCES user_account(user_id) 
                ON DELETE CASCADE,
                
            -- Add primary key
            CONSTRAINT pk_security_questions 
                PRIMARY KEY (user_id)
        );
        
        -- Create updated_at trigger
        CREATE TRIGGER update_security_questions_updated_at
            BEFORE UPDATE ON security_questions
            FOR EACH ROW
            EXECUTE FUNCTION trigger_set_timestamp();
            
        RAISE NOTICE 'Security questions table created successfully';
    ELSE
        RAISE NOTICE 'Security questions table already exists';
    END IF;
END $$;

-- Create trigger function if it doesn't exist
CREATE OR REPLACE FUNCTION trigger_set_timestamp()
RETURNS TRIGGER AS $$
BEGIN
  NEW.updated_at = CURRENT_TIMESTAMP;
  RETURN NEW;
END;
$$ LANGUAGE plpgsql;