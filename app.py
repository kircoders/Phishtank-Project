import streamlit as st
import pandas as pd
from urllib.parse import urlparse
import networkx as nx
import matplotlib.pyplot as plt

st.set_page_config(layout="wide")
st.title("Phishing Infrastructure Analysis (PhishTank)")

st.write(
    """
    This project analyzes phishing infrastructure using graph-based techniques on data from PhishTank. By modeling relationships 
    between IP addresses, phishing domains, and impersonated targets, the project explores how attackers reuse infrastructure, 
    rotate hosting to evade takedowns, and focus on high-value brands. Interactive, degree-filtered graphs are used to highlight 
    these behaviors while illustrating the limits of raw network visualization in cybersecurity analysis.
    
    Each tab answers a different security question:
    - IP reuse (which IPs hosted multiple domains?)
    - Domain rotation (Which domains rotated among multiple IPs?)
    - Target impersonation (Which websites were most targeted for impersonation?)

    The data used in this project was obtained from PhishTank, a community-driven repository of verified phishing URLs. Each entry 
    represents a reported phishing URL along with associated metadata such as the impersonated target and observed hosting 
    information. The dataset is ordered by submission time, with the most recently reported phishing URLs appearing first. For 
    this analysis, the first 300 (out of about 37000) entries were selected to focus on a recent snapshot of phishing activity while 
    keeping the visualizations manageable. While I only used the first 300 entries for this project, this might have been a slight
    limitation because it would only include entries from specific months of the year, and phishing attacks/patters CAN differ
    depending on the time of the year.

    NOTE: The data used has no personally identifying information (PII), and is from an ethical source (PhishTank)
    """
)

# -----------------------------
# Load & preprocess data ONCE
# -----------------------------

@st.cache_data
def load_data():
    df = pd.read_json("phishing_data.json")
    df = df.head(300)
    df = df[["phish_id", "url", "details", "target"]]

    def extract_ip(details):
        if isinstance(details, list) and len(details) > 0:
            return details[0].get("ip_address")
        return None

    def extract_domain(url):
        try:
            return urlparse(url).netloc
        except:
            return None

    df["ip"] = df["details"].apply(extract_ip)
    df["domain"] = df["url"].apply(extract_domain)

    return df

df = load_data()

@st.cache_data
def load_data_with_time():
    df = pd.read_json("phishing_data.json")
    df = df[["submission_time", "target"]]
    df["submission_time"] = pd.to_datetime(df["submission_time"])

    # Keep a sortable month key
    df["month_key"] = df["submission_time"].dt.to_period("M")

    # Human-readable label
    df["month_label"] = df["submission_time"].dt.strftime("%B %Y")

    return df


# -----------------------------
# Tabs
# -----------------------------

tab1, tab2, tab3, tab4 = st.tabs([
    "IP Infrastructure Reuse",
    "Domain Rotation",
    "Target Impersonation",
    "Phishing Targets by Month"
])

# ======================================================
# TAB 1 — IP ↔ Domain (Infrastructure Reuse)
# ======================================================

with tab1:
    st.header("IP Infrastructure Reuse (High-Degree IPs)")

    df1 = df.dropna(subset=["domain", "ip"])

    # Build full graph (same as before)
    G = nx.Graph()
    for _, row in df1.iterrows():
        domain = row["domain"]
        ip = row["ip"]

        G.add_node(domain, type="domain")
        G.add_node(ip, type="ip")
        G.add_edge(domain, ip, relation="HOSTED_ON")

    min_degree_ip = st.number_input(
        "I want IP addresses that are connected to at least how many domains?",
        min_value=1,
        max_value=100,
        value=5,
        step=1,
        help="How many minimum domains should the IP be connected to?"
    )

    high_degree_ips = [
        node for node, degree in G.degree()
        if degree > min_degree_ip and G.nodes[node]["type"] == "ip"
    ]

    nodes_to_draw = set()

    for ip in high_degree_ips:
        nodes_to_draw.add(ip)
        for neighbor in G.neighbors(ip):
            nodes_to_draw.add(neighbor)

    subgraph = G.subgraph(nodes_to_draw)

    st.write(f"High-degree IPs shown: {len(high_degree_ips)}")
    st.write(f"Total nodes shown: {subgraph.number_of_nodes()}")
    st.write(f"Total edges shown: {subgraph.number_of_edges()}")

    # ---- DRAW ----
    fig = plt.figure(figsize=(18, 14))

    pos = nx.spring_layout(
        subgraph,
        k=1.2,
        iterations=50,
        seed=42
    )

    node_colors_ip = []

    for node in subgraph.nodes():
        if subgraph.nodes[node]["type"] == "ip":
            node_colors_ip.append("tomato")      # IP addresses
        elif subgraph.nodes[node]["type"] == "domain":
            node_colors_ip.append("skyblue")     # Domains
        else:
            node_colors_ip.append("gray")        # Fallback

    nx.draw(
        subgraph,
        pos,
        with_labels=True,
        node_size=600,
        font_size=8,
        alpha=0.9,
        edge_color="gray",
        node_color=node_colors_ip
    )

    st.pyplot(fig)

    st.write(
        """
        **Graph Explanation:**  
        This graph seeks to connect IP addresses and all the domains connected to them. The point was to see which IP addresses
        have the most domains connected to them, as those IPs need to be monitored more. As you can see, this graph, called a 
        "hairball graph", is very messy and unreadable before filtering. But when the user filters to only include IP addresses
        that are connected to at least "n" domains, the graph becomes much more readable and it becomes much easier to see which
        IP addresses were used the most often.

        As we can see though, the IP address connected to the most domains was 172.67.152.91 (connected to 42 domains!). This is 
        a Cloudflare IP, which strongly indicates that phishers were using Cloudflare to host their sites. This is very likely 
        because Cloudflare provides HTTPS, makes takedowns harder, and it hides the real IP address that the attacker is using. 
        Other IP addresses, such as 104.21.1.216 (connected to 37 domains) are also Cloudflare. This does not mean that Cloudflare
        is compromised, but rather that attackers are using this infrastructure in order to host their sites. 

        Without Cloudflare, a phishing domain’s DNS records typically point directly to the attacker’s server. When a user connects
        to the phishing website, their browser establishes a direct connection to the server that is hosting the malicious content. 
        As a result, the real IP address of the phishing server is publicly visible to anyone who inspects the domain.

        WITH Cloudflare, however, the phishing domain’s DNS records point to Cloudflare’s IP addresses instead of the attacker’s 
        server. When a user connects to the phishing website, their browser connects to Cloudflare, which acts as a reverse proxy 
        between the user and the attacker’s server. Cloudflare then forwards the request to the hidden origin server and returns 
        the response to the user.

        In this setup, the real IP address of the phishing server is not publicly visible. To outside observers, the phishing 
        website appears to be hosted on Cloudflare infrastructure, even though the actual server is operated by the attacker. As 
        a result, investigators see Cloudflare’s shared IP addresses rather than the true hosting location of the phishing site.

        One might wonder why Cloudflare cannot just take down the site easily. Cloudflare can investigate and disable malicious 
        domains, but they must follow review processes to avoid false positives and legal issues. Because they operate at massive 
        scale with millions of domains, taking down phishing sites is slower than simply shutting down a server directly. 
        Additionally, Cloudflare cannot simply block a shared IP address as doing so would shut down many legitimate websites 
        hosted on the same infrastructure.
        """
    )

# ======================================================
# TAB 2 — Domain ↔ IP (Domain Rotation)
# ======================================================

with tab2:
    st.header("Domain Rotation (Domains using multiple IPs)")

    df2 = df.dropna(subset=["domain", "ip"])

    # Build full graph
    G = nx.Graph()
    for _, row in df2.iterrows():
        domain = row["domain"]
        ip = row["ip"]

        G.add_node(domain, type="domain")
        G.add_node(ip, type="ip")
        G.add_edge(domain, ip)

    # Step 1: find high-degree domains
    min_degree_domain = st.number_input(
        "I want domains that are connected to at least how many IP addresses?",
        min_value=1,
        max_value=10,
        value=5,
        step=1,
        help="How many minimum domains should the IP be connected to?"
    )

    high_degree_domains = [
        node for node, degree in G.degree()
        if degree >= min_degree_domain and G.nodes[node]["type"] == "domain"
    ]

    # Step 2: collect domains + connected IPs
    nodes_to_draw = set()

    for domain in high_degree_domains:
        nodes_to_draw.add(domain)
        for neighbor in G.neighbors(domain):
            nodes_to_draw.add(neighbor)

    subgraph = G.subgraph(nodes_to_draw)

    st.write(f"High-degree domains shown: {len(high_degree_domains)}")
    st.write(f"Total nodes shown: {subgraph.number_of_nodes()}")
    st.write(f"Total edges shown: {subgraph.number_of_edges()}")

    # Draw
    fig = plt.figure(figsize=(14, 12))
    pos = nx.spring_layout(subgraph, k=1.1, iterations=40, seed=42)

    node_colors_domain = []

    for node in subgraph.nodes():
        if subgraph.nodes[node]["type"] == "ip":
            node_colors_domain.append("tomato")      # IP addresses
        elif subgraph.nodes[node]["type"] == "domain":
            node_colors_domain.append("skyblue")     # Domains
        else:
            node_colors_domain.append("gray")        # Fallback

    nx.draw(
        subgraph,
        pos,
        with_labels=True,
        node_size=600,
        font_size=8,
        alpha=0.9,
        edge_color="gray",
        node_color=node_colors_domain
    )

    st.pyplot(fig)

    st.write(
        """
        **Graph Explanation:**  
        This graph seeks to connect phishing domains to the IP addresses they have been hosted on. The goal is to 
        identify domains that rotate across multiple IPs, which is a common technique used by attackers to extend 
        the lifetime of phishing campaigns. Domains that appear on more than one IP are generally more resilient, 
        as they can be quickly rehosted when infrastructure is taken down or blocked. Rotating IPs helps with blacklisting.
        If one IP is blocked, the domain can simply move to another IP.

        Unlike the IP infrastructure reuse graph, this visualization is less dense and does not form a large hairball. 
        Instead, it is composed of smaller clusters, where a single domain is connected to multiple IP addresses. 
        Each of these clusters represents a phishing domain that has been redeployed across different hosting infrastructure. 
        
        This graph also allows the user to filter to domains that have rotated to at least n number of IPs. The fact that 
        relatively few domains meet even a minimal rotation threshold (two IP addresses) suggests that most phishing campaigns 
        are not highly resilient. Many attackers seem to give up after the original infrastructure is taken down.

        One thing that's notable here is that the domain with the most IPs connected to it is docs.google.com (with 6 IP addresses!). 
        The inclusion of this, however, does not mean that Google Docs is compromised or that Google is hosting phishing 
        infrastructure. Instead, it usually means that attackers are using Google Docs as part of phishing campaigns (e.g. 
        using it as an intermediate landing page). Attackers love to use trusted infrastructure like Google Docs because it avoids
        the costs of hosting a website and it makes detection much harder. Additionally, defenders cannot block Google Docs as 
        it would disrupt many legitimate users and their content.

        One actual example of a phishing scam using Google Docs was when attackers sent phishing emails telling recipients they needed 
        to “update their Office 365 account.” When the victim clicked the link, it took them to a Google Docs Form that looked like a 
        legitimate Microsoft login page hosted inside Google’s service. The phishing form collected the victim’s credentials and sent 
        them to the attackers, all while using a docs.google.com URL that looked trusted and passed browser security checks.
        """
    )

# ======================================================
# TAB 3 — Domain ↔ Target (Impersonation)
# ======================================================

with tab3:
    st.header("Target Impersonation (High-Value Brands)")

    df3 = df.dropna(subset=["domain", "target"])

    # Build full graph
    G = nx.Graph()
    for _, row in df3.iterrows():
        domain = row["domain"]
        target = row["target"]

        G.add_node(domain, type="domain")
        G.add_node(target, type="target")
        G.add_edge(domain, target)

    # Step 1: find high-degree targets
    min_degree_target = st.number_input(
        "I want targets that are at least connected to how many domains?",
        min_value=1,
        max_value=200,
        value=5,
        step=1,
        help="How many minimum domains should the IP be connected to?"
    )

    high_degree_targets = [
        node for node, degree in G.degree()
        if degree >= min_degree_target and G.nodes[node]["type"] == "target"
    ]

    # Step 2: collect targets + connected domains
    nodes_to_draw = set()

    for target in high_degree_targets:
        nodes_to_draw.add(target)
        for neighbor in G.neighbors(target):
            nodes_to_draw.add(neighbor)

    subgraph = G.subgraph(nodes_to_draw)

    st.write(f"High-degree targets shown: {len(high_degree_targets)}")
    st.write(f"Total nodes shown: {subgraph.number_of_nodes()}")
    st.write(f"Total edges shown: {subgraph.number_of_edges()}")

    # Draw
    fig = plt.figure(figsize=(14, 12))
    pos = nx.spring_layout(subgraph, k=1.1, iterations=40, seed=42)

    node_colors_targets = []

    for node in subgraph.nodes():
        if subgraph.nodes[node]["type"] == "target":
            node_colors_targets.append("tomato")      # IP addresses
        elif subgraph.nodes[node]["type"] == "domain":
            node_colors_targets.append("skyblue")     # Domains
        else:
            node_colors_targets.append("gray")        # Fallback

    nx.draw(
        subgraph,
        pos,
        with_labels=True,
        node_size=600,
        font_size=8,
        alpha=0.9,
        edge_color="gray",
        node_color=node_colors_targets
    )

    st.pyplot(fig)

    st.write(
        """
        **Graph Explanation:**  
        This graph seeks to connect phishing domains to the brands or services they are attempting to impersonate. 
        The goal is to identify high-value targets that are repeatedly abused by phishing campaigns. Targets with a large 
        number of connected domains represent brands that attackers consistently attempt to exploit, often because they are 
        widely used and trusted by victims. As with the previous graphs, the user can filter to websites that were most targeted.

        The most prominent target on this graph is Allegro, a major e-commerce platform in Poland. Its high number of connected 
        phishing domains (34!) indicated that it was a huge target for attackers, likely because users frequently log in, conduct 
        payments, and expect transactional emails. Attackers exploit this familiarity by creating many disposable domains that 
        mimic Allegro in order to steal credentials or payment information. Other impersonated domains that showed up were Apple,
        Amazon, and the IRS.

        The graph also contains a large node labeled Other (with 207 connected domains). This represents phishing domains targeting 
        smaller, less well-known services that were not specifically categorized in the dataset. While these campaigns are less 
        visible than attacks on major brands, they still pose a risk, as many victims continue to fall for them. This underscores 
        the importance of user awareness and education to prevent phishing attacks.

        """
    )

with tab4:
    st.header("Monthly Phishing Targets")

    df_time = load_data_with_time()

    # Select month
    month_lookup = (
        df_time[["month_key", "month_label"]]
        .drop_duplicates()
        .sort_values("month_key", ascending=False)
    )

    selected_label = st.selectbox(
        "Select a month",
        month_lookup["month_label"]
    )

    selected_key = month_lookup[
        month_lookup["month_label"] == selected_label
    ]["month_key"].iloc[0]

    df_month = df_time[df_time["month_key"] == selected_key]


    # Count all targets
    target_counts = df_month["target"].value_counts()

    # Identify most targeted NON-"Other"
    non_other = target_counts[target_counts.index != "Other"]

    if not non_other.empty:
        st.markdown(
            f"### Most targeted named website: **{non_other.idxmax()}** ({non_other.max()} phishing URLs)"
        )
    else:
        st.markdown("### No named targets this month (only 'Other')")

    # -----------------------------
    # Graph: ALL targets for month
    # -----------------------------

    G = nx.Graph()
    for target, count in target_counts.items():
        G.add_node(target, count=count)

    fig = plt.figure(figsize=(12, 9))
    pos = nx.spring_layout(G, seed=42)

    node_sizes = [G.nodes[n]["count"] * 20 for n in G.nodes()]
    node_colors = ["lightgray" if n == "Other" else "skyblue" for n in G.nodes()]

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

    plt.title(f"Phishing Targets — {selected_label}")
    st.pyplot(fig)

    with st.expander("Show raw target counts"):
        st.dataframe(target_counts.reset_index(name="count"))

