import json
import requests
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from app.database.connection import get_connection

sys.stdout.reconfigure(line_buffering=True)

OLLAMA_URL = "http://localhost:11434/api/embeddings"
EMBED_MODEL = "nomic-embed-text"

def get_embedding(text: str):
    response = requests.post(
        OLLAMA_URL,
        json={"model": EMBED_MODEL, "prompt": text},
        timeout=30
    )
    response.raise_for_status()
    return response.json().get("embedding")

def process_pattern(pattern):
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
    emb = get_embedding(content)
    
    return (technique_id, name, description, tactics_str, json.dumps(emb))

def main():
    url = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
    print("Downloading ATT&CK data...")
    response = requests.get(url, timeout=30)
    data = response.json()
    
    patterns = [obj for obj in data.get("objects", []) if obj.get("type") == "attack-pattern"]
    total = len(patterns)
    print(f"Found {total} attack patterns. Importing...")
    
    conn = get_connection()
    cur = conn.cursor()
    
    success_count = 0
    with ThreadPoolExecutor(max_workers=5) as executor:
        futures = {executor.submit(process_pattern, p): p for p in patterns}
        
        for i, future in enumerate(as_completed(futures), start=1):
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
            except Exception as e:
                print(f"Error processing a pattern: {e}")
                
            if i % 50 == 0 or i == total:
                conn.commit()
                print(f"{i}/{total} imported...")
                
    cur.close()
    conn.close()
    print("Import complete.")

if __name__ == "__main__":
    main()
