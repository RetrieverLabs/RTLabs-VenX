import csv
import re

def clean_vendor_name(name):
    """
    Strips out common corporate suffixes so the text matches CISA/News feeds.
    Transforms 'Microsoft Corp.' -> 'Microsoft'
    """
    if not name:
        return ""
    
    # Remove leading/trailing whitespace
    name = name.strip()
    
    # Common corporate suffixes to strip out (case-insensitive)
    # The \b ensures we only match whole words (so 'Cisco' doesn't lose its 'co')
    suffixes = [
        r'\bcorp(oration)?\b\.?',
        r'\binc(orporated)?\b\.?',
        r'\bllc\b\.?',
        r'\bltd\b\.?',
        r'\bco(mpany)?\b\.?',
        r'\bintl\b\.?',
        r'\binternational\b\.?',
        r'\bsa\b\.?',
        r'\bpvt\b\.?'
    ]
    
    # Run through the suffixes and strip them out
    for suffix in suffixes:
        name = re.sub(suffix, '', name, flags=re.IGNORECASE)
    
    # Clean up any leftover trailing commas, periods, or double spaces
    name = re.sub(r'\s+', ' ', name) # collapse multi-spaces
    name = name.strip(',. ')
    
    return name

def process_raw_supplier_list(input_file="raw_suppliers.csv", output_file="vendors.csv"):
    seen_vendors = set()
    cleaned_rows = []
    
    print(f"[*] Reading raw vendor data from '{input_file}'...")
    
    try:
        with open(input_file, mode="r", encoding="utf-8-sig") as f:
            # Using Sniffer to automatically handle weird delimiters (like tabs or semicolons)
            sample = f.read(2048)
            f.seek(0)
            dialect = csv.Sniffer().sniff(sample) if sample else csv.excel
            
            reader = csv.reader(f, dialect)
            headers = [h.strip().lower() for h in next(reader)]
            
            # Dynamically look for where the vendor name might be hidden
            name_idx = 0
            possible_name_headers = ['name', 'vendor', 'supplier', 'company', 'organization']
            for p_head in possible_name_headers:
                if p_head in headers:
                    name_idx = headers.index(p_head)
                    break
            
            # Look for an existing criticality tier if it exists
            crit_idx = None
            for p_crit in ['criticality', 'tier', 'business_criticality', 'priority']:
                if p_crit in headers:
                    crit_idx = headers.index(p_crit)
                    break

            # Process the rows
            for row_num, row in enumerate(reader, start=2):
                if not row or len(row) <= name_idx:
                    continue
                
                # Clean the name
                raw_name = row[name_idx]
                clean_name = clean_vendor_name(raw_name)
                
                if not clean_name:
                    continue
                
                # Deduplicate
                if clean_name.lower() in seen_vendors:
                    continue
                seen_vendors.add(clean_name.lower())
                
                # Grab or default the criticality tier
                criticality = "Tier-3" # Safe default
                if crit_idx is not None and len(row) > crit_idx and row[crit_idx].strip():
                    criticality = row[crit_idx].strip()
                
                # Append formatted row (Name, Previous Score Defaulted to 0, Criticality)
                cleaned_rows.append({
                    "name": clean_name,
                    "previous_score": 0,
                    "business_criticality": criticality
                })
                
    except FileNotFoundError:
        print(f"[!] Error: Could not find '{input_file}'. Please place your raw file here.")
        return
    except Exception as e:
        print(f"[!] Parsing error: {e}")
        return

    # Write out the pristine formatted CSV
    print(f"[*] Writing {len(cleaned_rows)} unique, cleaned vendors to '{output_file}'...")
    with open(output_file, mode="w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["name", "previous_score", "business_criticality"])
        writer.writeheader()
        writer.writerows(cleaned_rows)
        
    print("[✓] Optimization complete! Your 'vendors.csv' is ready for the scoreboard script.")

if __name__ == "__main__":
    # Change "raw_suppliers.csv" to whatever your current export file is named
    process_raw_supplier_list("raw_suppliers.csv", "vendors.csv")