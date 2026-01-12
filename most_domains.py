import pandas as pd
import requests
from urllib.parse import urlparse
import networkx as nx
import matplotlib.pyplot as plt

# -----------------------------
# 1. Download PhishTank JSON
# -----------------------------

df = pd.read_json("phishing_data.json")

# -----------------------------
# 2. Trim dataset (IMPORTANT)
# -----------------------------

# I want the top 300 rows, I cannot deal with 14000 rows in total
df = df.head(300)

# -----------------------------
# 3. Keep only relevant columns
# -----------------------------

# I only care about THESE columns
df = df[["phish_id", "url", "submission_time", "details", "target"]]

# -----------------------------
# 4. Extract IP address
# -----------------------------

print(df.tail(10))
print(df.head(10))

def extract_ip(details):
    if isinstance(details, list) and len(details) > 0:
        return details[0].get("ip_address")
    return None

df["ip"] = df["details"].apply(extract_ip)

# -----------------------------
# 5. Extract domain from URL
# -----------------------------

def extract_domain(url):
    try:
        return urlparse(url).netloc
    except:
        return None

df["domain"] = df["url"].apply(extract_domain)

# -----------------------------
# 6. Final cleanup
# -----------------------------

df = df.dropna(subset=["domain", "ip"])

# -----------------------------
# 7. Build Infrastructure Graph (Domain ↔ IP)
# -----------------------------

G = nx.Graph()

for _, row in df.iterrows():
    domain = row["domain"]
    ip = row["ip"]

    # Add nodes
    G.add_node(domain, type="domain")
    G.add_node(ip, type="ip")

    # Add infrastructure edge
    G.add_edge(domain, ip, relation="HOSTED_ON")

# -----------------------------
# 8. Basic graph stats
# -----------------------------

print("Total nodes:", G.number_of_nodes())
print("Total edges:", G.number_of_edges())

# -----------------------------
# 9. Degree table
# -----------------------------

degree_dict = dict(G.degree())

degree_df = (
    pd.DataFrame(degree_dict.items(), columns=["node", "degree"])
    .sort_values(by="degree", ascending=False)
)

print("\nTop nodes by degree:")
print(degree_df.head(20))

# -----------------------------
# 10. Domain reuse table
# -----------------------------

domain_rows = []

for node, degree in G.degree():
    if G.nodes[node]["type"] == "domain":
        domain_rows.append({
            "domain": node,
            "ips_used": degree
        })

domain_df = (
    pd.DataFrame(domain_rows)
    .sort_values(by="ips_used", ascending=False)
)

print("\nTop domains by number of IPs used:")
print(domain_df.head(10))


# ---------------------------------------------------------------------------------------------------------------
# 11. Visualization LAST. We are visualizing the most used domains here
# ---------------------------------------------------------------------------------------------------------------

# Step 1: find high-degree domains
high_degree_domains = [
    node for node, degree in G.degree()
    if degree > 1 and G.nodes[node]["type"] == "domain"
]

# Step 2: collect domains + connected IPs
nodes_to_draw = set()

for domain in high_degree_domains:
    nodes_to_draw.add(domain)
    for neighbor in G.neighbors(domain):
        nodes_to_draw.add(neighbor)

subgraph = G.subgraph(nodes_to_draw)

# Step 3: draw
plt.figure(figsize=(12, 12))
pos = nx.spring_layout(subgraph, seed=42)

nx.draw(
    subgraph,
    pos,
    with_labels=True,
    node_size=1000,
    font_size=9
)

plt.title("High-Degree Domains and Connected IPs")
plt.show()

