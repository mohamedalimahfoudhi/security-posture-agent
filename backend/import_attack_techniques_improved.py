"""Improved MITRE ATT&CK import with filtering and retry logic."""
import json
import requests
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from app.database.connection import get_connection

sys.stdout.reconfigure(line_buffering=True)

OLLAMA_URL = "http://localhost:11434/api/embeddings"
EMBED_MODEL = "nomic-embed-text"

def get_embedding_with_retry(text: str, max_retries=3, retry_delay=2):
    """Get embedding with retry logic."""
    for attempt in range(max_retries):
        try:
            response = requests.post(
                OLLAMA_URL,
                json={"model": EMBED_MODEL, "prompt": text},
                timeout=30
            )
            response.raise_for_status()
            return response.json().get("embedding")
        except Exception as e:
            if attempt == max_retries - 1:
                raise
            print(f"  Embedding attempt {attempt + 1} failed: {e}. Retrying in {retry_delay}s...")
            time.sleep(retry_delay)
    return None

def process_pattern(pattern):
    """Process a single attack pattern with retry logic."""
    name = pattern.get("name", "")
    description = pattern.get("description", "")
    
    technique_id = None
    for ref in pattern.get("external_references", []):
        if ref.get("source_name") == "mitre-attack":
            technique_id = ref.get("external_id")
            break
            
    if not technique_id:
        return None
        
    tactics = []
    for phase in pattern.get("kill_chain_phases", []):
        if phase.get("kill_chain_name") == "mitre-attack":
            tactics.append(phase.get("phase_name"))
    tactics_str = ",".join(tactics)
    
    content = f"Name: {name}. Description: {description}"
    
    try:
        emb = get_embedding_with_retry(content)
        if emb is None:
            print(f"  Failed to get embedding for {technique_id} after retries")
            return None
    except Exception as e:
        print(f"  Failed to process {technique_id}: {e}")
        return None
    
    return (technique_id, name, description, tactics_str, json.dumps(emb))

def main():
    url = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
    print("Downloading ATT&CK data...")
    response = requests.get(url, timeout=30)
    data = response.json()
    
    # Filter patterns: only attack-pattern, not revoked, not deprecated
    patterns = [
        obj for obj in data.get("objects", []) 
        if obj.get("type") == "attack-pattern" 
        and not obj.get("revoked") 
        and not obj.get("x_mitre_deprecated")
    ]
    
    total = len(patterns)
    print(f"Found {total} attack patterns (clean, not revoked/deprecated). Importing...")
    
    conn = get_connection()
    cur = conn.cursor()
    
    success_count = 0
    failed_ids = []
    
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {executor.submit(process_pattern, p): p for p in patterns}
        
        for i, future in enumerate(as_completed(futures), start=1):
            pattern = futures[future]
            technique_id = None
            for ref in pattern.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    technique_id = ref.get("external_id")
                    break
            
            try:
                result = future.result()
                if result:
                    technique_id, name, description, tactics_str, emb_json = result
                    cur.execute("""
                        INSERT INTO attack_techniques (technique_id, name, description, tactics, embedding)
                        VALUES (%s, %s, %s, %s, %s)
                        ON CONFLICT (technique_id) 
                        DO UPDATE SET 
                            name = EXCLUDED.name, 
                            description = EXCLUDED.description, 
                            tactics = EXCLUDED.tactics, 
                            embedding = EXCLUDED.embedding
                    """, (technique_id, name, description, tactics_str, emb_json))
                    success_count += 1
                else:
                    if technique_id:
                        failed_ids.append(technique_id)
            except Exception as e:
                if technique_id:
                    failed_ids.append(technique_id)
                print(f"Error processing pattern {technique_id or 'unknown'}: {e}")
                
            if i % 50 == 0 or i == total:
                conn.commit()
                print(f"{i}/{total} imported...")
                
    cur.close()
    conn.close()
    
    print(f"\nImport complete. {success_count}/{total} succeeded.")
    if failed_ids:
        print(f"Failed IDs ({len(failed_ids)}): {failed_ids}")
    else:
        print("All techniques imported successfully.")

if __name__ == "__main__":
    main()
