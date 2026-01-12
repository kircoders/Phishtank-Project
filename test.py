import streamlit as st
import pandas as pd
import networkx as nx
import matplotlib.pyplot as plt


# -----------------------------
# Load data
# -----------------------------

@st.cache_data
def load_data():
    df = pd.read_json("phishing_data.json")
    df = df[["phish_id", "submission_time", "target"]]
    df["submission_time"] = pd.to_datetime(df["submission_time"])
    df["month"] = df["submission_time"].dt.to_period("M").astype(str)
    return df


df = load_data()

st.title("Monthly Phishing Targets (Exploratory View)")

# -----------------------------
# Month selector
# -----------------------------

months = sorted(df["month"].unique(), reverse=True)
selected_month = st.selectbox("Select a month", months)

df_month = df[df["month"] == selected_month]

# -----------------------------
# Count targets
# -----------------------------

target_counts = df_month["target"].value_counts()

# Identify top non-"Other" target (THE ANSWER)
non_other = target_counts[target_counts.index != "Other"]

if not non_other.empty:
    top_target = non_other.idxmax()
    top_count = non_other.max()
    st.markdown(
        f"### Most targeted *named* website: **{top_target}** ({top_count} phishing URLs)"
    )
else:
    st.markdown("### No named targets this month (only 'Other')")

# -----------------------------
# Build graph (ALL targets)
# -----------------------------

G = nx.Graph()

for target, count in target_counts.items():
    G.add_node(target, count=count)

# -----------------------------
# Draw graph
# -----------------------------

fig = plt.figure(figsize=(10, 8))
pos = nx.spring_layout(G, seed=42)

node_sizes = []
node_colors = []

for n in G.nodes():
    count = G.nodes[n]["count"]
    node_sizes.append(count * 20)

    if n == "Other":
        node_colors.append("lightgray")
    else:
        node_colors.append("skyblue")

nx.draw(
    G,
    pos,
    with_labels=True,
    node_size=node_sizes,
    node_color=node_colors,
    font_size=9,
    edge_color="white",
    alpha=0.9
)

plt.title(f"Phishing Targets – {selected_month}")
st.pyplot(fig)

# -----------------------------
# Optional table (for sanity)
# -----------------------------

with st.expander("Show raw counts"):
    st.dataframe(target_counts.reset_index(name="count"))
