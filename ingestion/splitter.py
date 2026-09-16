def parse_ufw_line(line):
    info_table = {
        "timestamp": None,
        "action": None,
        "src_ip": None,
        "dst_ip": None,
        "protocol": None,
        "src_prt": None,
        "dst_prt": None 
    }
    
    parts = line.split()

    if len(parts) > 0:
        info_table["timestamp"] = parts[0]

    if "[UFW BLOCK]" in line:    
        info_table["action"] = "BLOCK"
    elif "[UFW ALLOW]" in line:
        info_table["action"] = "ALLOW"
    elif "[UFW AUDIT]" in line:
        info_table["action"] = "AUDIT"

    for part in parts:
        if "=" in part:
            key, value = part.split("=", 1)

            if key == "SRC":
                info_table["src_ip"] = value
            
            elif key == "DST":
                info_table["dst_ip"] = value
            
            elif key == "PROTO":
                info_table["protocol"] = value

            elif key == "SPT":
                info_table["src_prt"] = value
            
            elif key == "DPT":
                info_table["dst_prt"] = value
    
    return info_table
            

