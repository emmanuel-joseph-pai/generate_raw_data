import json
import random
from datetime import datetime, timedelta

def generate_hex_id():
    return ''.join([random.choice('0123456789abcdef') for _ in range(64)])

def generate_timestamp():
    # Generate a random datetime object
    timestamp = datetime.now() - timedelta(days=random.randint(0, 10))
    # Restrict millisecond value to either 100 or 900
    restricted_millisecond = 100 if (timestamp.microsecond // 1000) % 2 == 0 else 900
    # Return it in the required format with restricted milliseconds
    return timestamp.strftime("%Y-%m-%d %H:%M:%S.") + f"{restricted_millisecond:03}"  # Milliseconds are added here

def generate_graph_id(p_id, updated_at_ts):
    return f"{p_id}_{updated_at_ts}"

def generate_test_data():
    data = {
        "host": [],
        "vulnerability": [],
        "identity": [],
        "person": []
    }

    for _ in range(100):
        timestamp = generate_timestamp()  # This is now a formatted string

        # Host data
        host = {
            "p_id": generate_hex_id(),
            "host_name": f"host-{random.randint(1000, 9999)}",
            "ip_address": f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
            "os_version": f"{random.choice(['Windows', 'Linux', 'MacOS'])} {random.randint(1, 10)}.{random.randint(0, 9)}",
            "type": random.choice(["Server", "Hypervisor", "Network Device", "Workstation","Unknown",None]),
            "infrastructure_type": random.choice(["Physical", "Unknown", "Virtual",None]),
            "accessibility": random.choice(["External", "Internal"]),
            "cloud_provider": random.choice(["Azure", "AWS","GCP"]),
            "os_family": random.choice(["Windows", "Other","Network OS","Linux","Android","macOS","iOS",None]),
            "operational_state": random.choice(["Active", "Disabled"]),
            "cpu_cores": random.randint(1, 16),
            "recency": random.randint(0, 100),
            "lifetime": random.randint(0, 1000),
            "ram_gb": random.randint(4, 64),
            "is_active": random.choice([True, False]),
            "last_seen": timestamp,
            "tags": [f"tag{i}" for i in range(random.randint(1, 5))],
            "updated_at_ts": timestamp
        }
        host["graph_id"] = generate_graph_id(host["p_id"], host["updated_at_ts"])
        data["host"].append(host)

        # Vulnerability data
        vulnerability = {
            "p_id": generate_hex_id(),
            "cve_id": f"CVE-{random.randint(2000, 2023)}-{random.randint(1000, 9999)}",
            "severity": random.choice(["Low", "Medium", "High", "Critical",None]),
            "description": f"Test vulnerability description {random.randint(1, 100)}",
            "normalised_v2severity": random.choice(["Low", "Medium", "High", "Critical"]),
            "exploit_available": random.choice(["True", "False"]),
            "vendor_severity": random.choice(["Low", "Medium", "High", "Critical"]),
            "affected_systems": random.randint(1, 1000),
            "recency": random.randint(0, 100),
            "lifetime": random.randint(0, 1000),
            "patch_available": random.choice([True, False]),
            "discovery_date": timestamp,
            "cvss_score": round(random.uniform(0, 10), 1),
            "affected_versions": [f"{random.randint(1, 10)}.{random.randint(0, 9)}" for _ in range(random.randint(1, 3))],
            "updated_at_ts": timestamp
        }
        vulnerability["graph_id"] = generate_graph_id(vulnerability["p_id"], vulnerability["updated_at_ts"])
        data["vulnerability"].append(vulnerability)

        # Identity data
        identity = {
            "p_id": generate_hex_id(),
            "username": f"user{random.randint(100, 999)}",
            "email": f"user{random.randint(100, 999)}@example.com",
            "role": random.choice(["Admin", "User", "Guest",None]),
            "last_login": timestamp,
            "recency": random.randint(0, 100),
            "operational_status": random.choice(["Active", "Inactive","Unknown"]),
            "account_ownership": random.choice(["External", "Corp"]),
            "account_created": (datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S.%f") - timedelta(days=random.randint(1, 1000))),
            "is_active": random.choice([True, False]),
            "login_attempts": random.randint(10,20),
            "permissions": [f"perm{i}" for i in range(random.randint(1, 5))],
            "updated_at_ts": timestamp
        }
        identity["graph_id"] = generate_graph_id(identity["p_id"], identity["updated_at_ts"])
        data["identity"].append(identity)

        # Person data
        person = {
            "p_id": generate_hex_id(),
            "full_name": f"{random.choice(['John', 'Jane', 'Alice', 'Bob', 'Charlie'])} {random.choice(['Smith', 'Johnson', 'Williams', 'Brown', 'Jones'])}",
            "job_title": random.choice(["Engineer", "Manager", "Analyst", "Developer", "Designer",None]),
            "department": random.choice(["IT", "HR", "Finance", "Marketing", "Sales"]),
            "employee_id": f"EMP{random.randint(1000, 9999)}",
            "recency": random.randint(0, 100),
            "employee_status": random.choice(["Active", "Applicant", "Inactive", "Leave of Absence","No Hire",None]),
            "hire_date": (datetime.strptime(timestamp, "%Y-%m-%d %H:%M:%S.%f") - timedelta(days=random.randint(1, 3650))),
            "is_active": random.choice([True, False]),
            "manager": f"{random.choice(['John', 'Jane', 'Alice', 'Bob', 'Charlie'])} {random.choice(['Smith', 'Johnson', 'Williams', 'Brown', 'Jones'])}",
            "location": random.choice(["New York", "London", "Tokyo", "Paris", "Sydney",None]),
            "updated_at_ts": timestamp
        }
        person["graph_id"] = generate_graph_id(person["p_id"], person["updated_at_ts"])
        data["person"].append(person)

    return data

# Relationship data generation
def generate_relationship_data(entities):
    relationships = [
        "Host_Has_Vulnerability",
        "Host_Has_Identity",
        "Person_Owns_Host",
        "Person_Has_Identity",
    ]

    relationship_data = {}

    for rel in relationships:
        source_entity, target_entity = rel.split('_')[0], rel.split('_')[-1]

        relationship_data[rel] = []

        for i in range(min(len(entities[source_entity.lower()]), len(entities[target_entity.lower()]))):
            source = entities[source_entity.lower()][i]
            target = entities[target_entity.lower()][i]
            timestamp = generate_timestamp()
            possible_sources = ["Log Analysis", "Network Scan", "User Report", "System Inventory", "Vulnerability Scanner"]

            relationship = {
                "relationship_id": generate_hex_id(),
                "source_id": source["p_id"],
                "target_id": target["p_id"],
                "relationship_type": rel,
                "strength": random.uniform(0, 1),
                "last_updated": generate_timestamp(),
                "is_active": bool(i % 2),
                "graph_id": f"{rel}_{i}_{generate_timestamp()}",
                "source_graph_id": source["graph_id"],
                "target_graph_id": target["graph_id"],
                "relationship_origin": random.sample(possible_sources, random.randint(1, 3)),
                "updated_at_ts": timestamp,
                "relationship_first_seen_date": generate_timestamp(),
                "relationship_last_seen_date": generate_timestamp(),
                "lifetime_relationship": random.randint(1, 365),
                "software_full_name": f"{random.choice(['adobe illustrator', 'freeradius', 'python pip','google chrome','adobe acrobat','php','microsoft dynamics','openexr'])} {random.randint(1, 10)}.{random.randint(0, 9)}",
                "recency_relationship": random.randint(1, 30),
                "software_product": random.choice(["searchblox", "gentoo nextcloud","debian graphite2","heroiclabs nakama","redhat cloud-init","htmlunit","apache oozie",None,"openzeppelin-eth","vertica","dotproject"]),
                "relationship_fragments": random.randint(1, 10),
                "software_version": f"{random.randint(0, 9)}.{random.randint(1, 99)}.{random.randint(20, 1000)}",
                "software_vendor": random.choice(["extremail", "acdsee","addressable project","libass project","opennms","barrier project","panda",None,"mutt","bufferlist project","spgpartenaires"]),
                "source_display_label": source.get("host_name", source.get("full_name", source.get("cve_id", ""))),
                "target_display_label": target.get("host_name", target.get("full_name", target.get("cve_id", "")))
            }

            if rel == "Host_Has_Vulnerability":
                relationship.update({
                    "vulnerability_fixed_date": generate_timestamp(),
                    "vulnerability_latest_open_date": generate_timestamp(),
                    "current_status":random.choice(["Closed", "Open"]),
                    "sla_duration": random.randint(1, 550),
                    "sla_flag":random.choice(["false", "true"])
                })

            relationship_data[rel].append(relationship)

    return relationship_data

# Custom JSON serialization function for datetime objects
def datetime_serializer(obj):
    if isinstance(obj, datetime):
        return obj.strftime("%Y-%m-%d %H:%M:%S.%f")  # Format datetime to string
    raise TypeError(f"Type {type(obj)} not serializable")

# Function to write data in newline-delimited JSON format
def write_json_lines(file_path, data):
    with open(file_path, 'w') as f:
        for item in data:
            json.dump(item, f, default=datetime_serializer, indent=None)  # write item without indent and handle datetime serialization
            f.write('\n')  # write each JSON object in a new line

def main():
    # Generate test data and relationship data
    test_data = generate_test_data()
    relationship_data = generate_relationship_data(test_data)

    # Save each entity into its respective newline-delimited JSON file
    write_json_lines('C:/Users/emmanuel.joseph/Desktop/PG_test_data/sds_ei__host.json', test_data["host"])
    write_json_lines('C:/Users/emmanuel.joseph/Desktop/PG_test_data/sds_ei__vulnerability.json', test_data["vulnerability"])
    write_json_lines('C:/Users/emmanuel.joseph/Desktop/PG_test_data/sds_ei__identity.json', test_data["identity"])
    write_json_lines('C:/Users/emmanuel.joseph/Desktop/PG_test_data/sds_ei__person.json', test_data["person"])

    # Save relationships into a newline-delimited JSON file
    write_json_lines('C:/Users/emmanuel.joseph/Desktop/PG_test_data/sds_ei__rel__host_has_vulnerability.json', relationship_data["Host_Has_Vulnerability"])
    write_json_lines('C:/Users/emmanuel.joseph/Desktop/PG_test_data/sds_ei__rel__host_has_identity.json', relationship_data["Host_Has_Identity"])
    write_json_lines('C:/Users/emmanuel.joseph/Desktop/PG_test_data/sds_ei__rel__person_owns_host.json', relationship_data["Person_Owns_Host"])
    write_json_lines('C:/Users/emmanuel.joseph/Desktop/PG_test_data/sds_ei__rel__person_has_identity.json', relationship_data["Person_Has_Identity"])

    print("Test data and relationships have been generated and saved to combined_test_data.json")

if __name__ == "__main__":
    main()
