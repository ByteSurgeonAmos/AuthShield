import { NestFactory } from '@nestjs/core';
import { AppModule } from './app.module';
import { DataSource } from 'typeorm';

async function runMigration() {
  const app = await NestFactory.create(AppModule);
  const dataSource = app.get(DataSource);

  try {
    const tableExists = await dataSource.query(
      `SELECT EXISTS (
        SELECT FROM information_schema.tables 
        WHERE table_name = 'security_questions'
      )`,
    );

    if (!tableExists[0].exists) {
      console.log('Creating security_questions table...');

      await dataSource.query(`
        CREATE TABLE security_questions (
          user_id VARCHAR NOT NULL,
          question VARCHAR NOT NULL,
          answer_hash VARCHAR NOT NULL,
          is_changed BOOLEAN NOT NULL DEFAULT FALSE,
          created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
          updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
          
          CONSTRAINT fk_security_questions_user_id 
            FOREIGN KEY (user_id) 
            REFERENCES user_account(user_id) 
            ON DELETE CASCADE,
            
          CONSTRAINT pk_security_questions 
            PRIMARY KEY (user_id)
        )
      `);

      console.log('Security questions table created successfully!');
    } else {
      console.log('Security questions table already exists');
    }
  } catch (error) {
    console.error('Migration failed:', error);
  } finally {
    await app.close();
  }
}

runMigration();
