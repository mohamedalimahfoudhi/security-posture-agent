# AI-TIP Project Restore Instructions

Follow these steps to restore the database dump and run the AI-TIP project locally with real data.

## 1. Prerequisites
- **PostgreSQL** must be installed and running on your local machine.
- Command-line tools like `createdb` and `psql` should be available in your system PATH.

## 2. Restore the Database Dump
Open your terminal and run the following commands to create a fresh local database and restore the dump:

```bash
# Create a fresh database named ai_tip_local
createdb ai_tip_local

# Restore the dump file into the new database
psql -d ai_tip_local -f ai_tip_dump_2026-07-27.sql
```
*(If your local PostgreSQL requires a specific username or password, add `-U your_username` and supply the password when prompted).*

## 3. Update Environment Variables (`.env`)
To point the application to your new local database instead of the shared VM, update your `.env` file with your local credentials. 

**IMPORTANT:** Set your own local Postgres credentials. Do NOT use the real project ones.

```env
DB_HOST=localhost
DB_NAME=ai_tip_local
DB_USER=your_local_postgres_user
DB_PASSWORD=your_local_postgres_password
```

## 4. Local AI Setup
If you want the AI features (e.g., automated risk assessments, correlation engine) to work fully, you must have **Ollama** running locally with the required models pulled.

Run the following commands to ensure you have the models:
```bash
ollama pull qwen2.5:0.5b
ollama pull nomic-embed-text
```

Once the database is restored, your `.env` is updated, and the models are pulled, you are ready to run the project locally!
