with open('app/ai/graph_rag.py', 'r', encoding='utf-8') as f:
    content = f.read()

# The line became unindented when we moved the vendor_count query above the early return.
# It should be indented 4 spaces (inside the function body).
old = '\ncur.execute("SELECT COUNT(*) FROM customer_vendors WHERE customer_id = %s", (customer_id,))'
new = '\n    cur.execute("SELECT COUNT(*) FROM customer_vendors WHERE customer_id = %s", (customer_id,))'

if old in content:
    content = content.replace(old, new)
    print("Fixed indentation of vendor_count query")
else:
    print("Pattern not found - checking current state")
    # Show the lines around the issue
    for i, line in enumerate(content.splitlines()):
        if 'customer_vendors WHERE customer_id' in line:
            print(f"Line {i}: {repr(line)}")

with open('app/ai/graph_rag.py', 'w', encoding='utf-8') as f:
    f.write(content)
print("Done")
