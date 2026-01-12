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

df = df.head(300)

# -----------------------------
# 3. Keep only relevant columns
# -----------------------------

df = df[["phish_id", "url", "submission_time", "details", "target"]]

# -----------------------------
# 4. Extract domain from URL
# -----------------------------

def extract_domain(url):
    try:
        return urlparse(url).netloc
    except:
        return None

df["domain"] = df["url"].apply(extract_domain)

# -----------------------------
# 5. Final cleanup
# -----------------------------

df = df.dropna(subset=["domain", "target"])

# -----------------------------
# 6. Build Infrastructure Graph (Domain ↔ target)
# -----------------------------

G = nx.Graph()

for _, row in df.iterrows():
    domain = row["domain"]
    target = row["target"]

    # Add nodes
    G.add_node(domain, type="domain")
    G.add_node(target, type="target")

    # Add infrastructure edge
    G.add_edge(domain, target, relation="IS_IMPERSONATING")

# -----------------------------
# 7. Basic graph stats
# -----------------------------

print("Total nodes:", G.number_of_nodes())
print("Total edges:", G.number_of_edges())

# -----------------------------
# 8. Degree table
# -----------------------------

degree_dict = dict(G.degree())

degree_df = (
    pd.DataFrame(degree_dict.items(), columns=["node", "degree"])
    .sort_values(by="degree", ascending=False)
)

print("\nTop nodes by degree:")
print(degree_df.head(20))

# -----------------------------
# 9. Target reuse table
# -----------------------------

target_rows = []

for node, degree in G.degree():
    if G.nodes[node]["type"] == "target":
        target_rows.append({
            "target": node,
            "phishing_domains_hosted": degree
        })

target_df = (
    pd.DataFrame(target_rows)
    .sort_values(by="phishing_domains_hosted", ascending=False)
)

print("\nTop targets by phishing domain count:")
print(target_df.head(10))

# -----------------------------
# 10. Visualization LAST
# -----------------------------

# Step 1: find high-degree Targets
high_degree_targets = [
    node for node, degree in G.degree()
    if degree > 5 and G.nodes[node]["type"] == "target"
]

# Step 2: collect Targets + all connected domains
nodes_to_draw = set()

for target in high_degree_targets:
    nodes_to_draw.add(target)
    for neighbor in G.neighbors(target):
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

plt.title("High-Degree Targets and Connected Phishing Domains")
plt.show()

