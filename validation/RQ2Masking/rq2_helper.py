###############################################################
#   PowerGuard RQ2 Clustering & Visualization Helper Module   #
###############################################################

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from sklearn.metrics import silhouette_score

# Try importing adjustText for smart label placement
try:
    from adjustText import adjust_text
    HAS_ADJUST_TEXT = True
except ImportError:
    HAS_ADJUST_TEXT = False
    print("Warning: 'adjustText' library not found. Labels in scatter plots may overlap.")
    print("Suggestion: pip install adjustText")

# Try importing UMAP
try:
    import umap
    HAS_UMAP = True
except ImportError:
    HAS_UMAP = False
    print("Warning: 'umap-learn' not found. UMAP projection will be skipped.")
    print("Suggestion: pip install umap-learn")


# Paths (Update these if running on a different machine)
DATA_PATH = "../../data/RQ2/background_traffic_full.csv"
PERF_PATH = "../../data/RQ2/f1res.csv"

###############################################################
# 1. Feature Definitions (Updated with Structural Features)
###############################################################

ALL_FEATURES = [
    # Volume & Variance
    'pps_idle','pps_active',
    'pps_var_idle','pps_var_active',
    'num_packets_idle','num_packets_active',
    'burst_count_idle','burst_count_active',

    # Packet Size Dynamics
    'size_mean_idle','size_mean_active',
    'size_var_idle','size_var_active',
    'size_kurt_idle','size_kurt_active',

    # Timing (IAT)
    'iat_mean_idle','iat_mean_active',
    'iat_var_idle','iat_var_active',

    # Protocols
    'proto_tls_idle','proto_tls_active',
    'proto_tcp_idle','proto_tcp_active',
    'proto_udp_idle','proto_udp_active',
    'proto_mdns_idle','proto_mdns_active',
    'proto_ssdp_idle','proto_ssdp_active',
    'proto_arp_idle','proto_arp_active',
    'proto_dhcp_idle','proto_dhcp_active',
    'proto_other_idle','proto_other_active',

    # Flows & Structure
    'num_flows_idle','num_flows_active',
    'mean_pkts_per_flow_idle','mean_pkts_per_flow_active',
    'top_flow_frac_idle','top_flow_frac_active',
    'flow_entropy_idle','flow_entropy_active',
    'num_dst_ips_idle','num_dst_ips_active',
    'num_dst_ports_idle','num_dst_ports_active',

    # Direction & Strength
    'inout_ratio_idle','inout_ratio_active',
    'bts_idle','bts_active'
]

IDLE_FEATURES = [f for f in ALL_FEATURES if f.endswith("_idle")]
ACTIVE_FEATURES = [f for f in ALL_FEATURES if f.endswith("_active")]


###############################################################
# 2. Step 1 — K Selection (Elbow + Silhouette)
###############################################################

def plot_k_selection(mode="both", k_min=2, k_max=12, csv_path=DATA_PATH):
    """
    Generates Elbow and Silhouette plots to determine optimal K.
    """
    if mode == "idle":
        features = IDLE_FEATURES
        title = "Idle Only"
    elif mode == "active":
        features = ACTIVE_FEATURES
        title = "Active Only"
    else:
        features = ALL_FEATURES
        title = "Idle + Active"

    print(f"\n--- K Selection Mode: {title} ---")

    # Load and clean
    df = pd.read_csv(csv_path)
    # Filter only columns that actually exist in the CSV to prevent errors
    available_feats = [f for f in features if f in df.columns]
    X = df[available_feats].apply(pd.to_numeric, errors="coerce").fillna(0)

    # Scale & PCA
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    pca = PCA(n_components=0.9)
    X_pca = pca.fit_transform(X_scaled)
    print(f"Reduced dimensions from {X.shape[1]} to {X_pca.shape[1]}")

    inertias = []
    silhouettes = []
    Ks = range(k_min, k_max + 1)

    for k in Ks:
        km = KMeans(n_clusters=k, n_init=20, random_state=42)
        labels = km.fit_predict(X_pca)
        inertias.append(km.inertia_)
        silhouettes.append(silhouette_score(X_pca, labels))

    # Plot
    fig, ax1 = plt.subplots(figsize=(10, 6))

    ax1.set_xlabel("Number of Clusters (k)")
    ax1.set_ylabel("Inertia (Elbow)", color="tab:blue")
    ax1.plot(Ks, inertias, marker="o", color="tab:blue")
    ax1.tick_params(axis='y', labelcolor="tab:blue")
    ax1.grid(True)

    ax2 = ax1.twinx()
    ax2.set_ylabel("Silhouette Score", color="tab:red")
    ax2.plot(Ks, silhouettes, marker="s", linestyle="--", color="tab:red")
    ax2.tick_params(axis='y', labelcolor="tab:red")

    plt.title(f"Optimal K Selection ({title})")
    plt.tight_layout()
    plt.savefig("rq2_k_selection.pdf", dpi=300)
    plt.show()

    best_k = Ks[np.argmax(silhouettes)]
    print(f"> Recommended Best K (Silhouette): {best_k}")
    return inertias, silhouettes


###############################################################
# 3. Step 2 — Final Clustering & Heatmap
###############################################################

def run_final_clustering(k=6, mode="both", csv_path=DATA_PATH):
    """
    Runs KMeans with chosen K and generates the Feature Heatmap.
    """
    df = pd.read_csv(csv_path)

    if mode == "idle":
        features = IDLE_FEATURES
        title = "Idle Only"
    elif mode == "active":
        features = ACTIVE_FEATURES
        title = "Active Only"
    else:
        features = ALL_FEATURES
        title = "Idle + Active"

    print(f"\n--- Running Final Clustering: K={k}, Mode={title} ---")

    available_feats = [f for f in features if f in df.columns]
    X = df[available_feats].apply(pd.to_numeric, errors="coerce").fillna(0)

    # Pipeline
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    pca = PCA(n_components=0.95)
    X_pca = pca.fit_transform(X_scaled)

    # Clustering
    km = KMeans(n_clusters=k, n_init=50, random_state=42)
    labels = km.fit_predict(X_pca)

    df["cluster_id"] = labels

    # Create Heatmap Data (Z-Scores)
    X_scaled_df = pd.DataFrame(X_scaled, columns=available_feats)
    X_scaled_df["cluster_id"] = labels
    cluster_profiles = X_scaled_df.groupby("cluster_id").mean()

    # Plot Heatmap
    plt.figure(figsize=(16, 12))
    sns.heatmap(cluster_profiles.T, cmap="RdBu_r", center=0, 
                linewidths=0.5, linecolor='lightgrey')
    plt.title(f"Cluster Behavioral Fingerprint (K={k}, {title})")
    plt.xlabel("Cluster ID")
    plt.tight_layout()
    plt.savefig("rq2_feature_heatmap.pdf", dpi=300)
    plt.show()

    return df, cluster_profiles


###############################################################
# 4. Step 3 — Performance Plot (Dumbbell)
###############################################################

def plot_cluster_performance(df_clusters, perf_csv=PERF_PATH):
    """
    Merges clustering result with F1 scores to plot the Dumbbell Chart.
    """
    # Load Performance Data
    perf = pd.read_csv(perf_csv)
    
    # Clean percentage strings (e.g. "90%" -> 90)
    cols_to_clean = [c for c in perf.columns if "f1" in c.lower()]
    for col in cols_to_clean:
        if perf[col].dtype == object:
            perf[col] = perf[col].str.replace("%", "").astype(float)
    
    # Merge
    # Ensure device names match. If merge yields empty df, check device names.
    df = pd.merge(df_clusters[['device', 'cluster_id']], perf, on="device", how="inner")
    
    if df.empty:
        print("Error: Merge resulted in empty dataframe. Check device name consistency between CSVs.")
        return

    # Calculate Drop
    df["Difference"] = df["f1_idle"] - df["f1_active"]

    # Mapping
    cluster_map = {cid: f"C{cid}" for cid in sorted(df["cluster_id"].unique())}
    df["Cluster_Label"] = df["cluster_id"].map(cluster_map)

    # Sort for plotting: Group by Cluster, then by Gap size
    df_sorted = df.sort_values(["cluster_id", "Difference"], ascending=[True, False]).reset_index(drop=True)

    # Plot Setup
    devices = df_sorted["device"].values
    x = np.arange(len(devices))
    y_idle = df_sorted["f1_idle"]
    y_active = df_sorted["f1_active"]

    fig, ax = plt.subplots(figsize=(20, 10))

    # Background Zones
    bg_colors = ['#ffffff', '#f0f0f0'] 
    groups = df_sorted.groupby("cluster_id")

    for i, (cid, group) in enumerate(groups):
        idxs = group.index
        start, end = idxs[0] - 0.5, idxs[-1] + 0.5
        ax.axvspan(start, end, facecolor=bg_colors[i % 2], alpha=1.0, zorder=0)

        # Label at top
        mid = (start + end) / 2
        y_text = 112
        ax.text(mid, y_text, cluster_map[cid], ha="center", fontsize=20, fontweight="bold", color="#333")

    # Dumbbell Lines & Dots
    ax.vlines(x, y_active, y_idle, color="#525252", linewidth=2, alpha=0.6, zorder=1)
    ax.scatter(x, y_idle, s=150, color="#bdbdbd", label="Idle Baseline", zorder=2, edgecolors='grey')
    ax.scatter(x, y_active, s=150, color="#d62728", label="Active (Masked)", zorder=3, edgecolors='maroon')

    # Styling
    ax.set_ylim(40, 118)
    ax.set_ylabel("F1 Score (%)", fontsize=26)
    ax.set_xticks(x)
    ax.set_xticklabels(devices, rotation=90, fontsize=16)
    ax.tick_params(axis='y', labelsize=20)
    
    # Legend
    ax.legend(loc='lower left', fontsize=18, frameon=True, framealpha=0.9)
    ax.grid(axis="y", linestyle="--", alpha=0.5)
    sns.despine()

    plt.tight_layout()
    plt.savefig("rq2_dumbbell_performance.pdf", dpi=300)
    plt.show()

    return df_sorted


###############################################################
# 5. Step 4 — Cluster Embedding (PCA/UMAP Visualization)
###############################################################
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from scipy.spatial import ConvexHull
import umap.umap_ as umap


def plot_cluster_embedding(df, feature_cols=None, title_prefix="Cluster"):
    
    df = df.copy()

    if feature_cols is None:
        feature_cols = [
            c for c in df.columns
            if c not in ["device", "category", "cluster_id"]
        ]

    X = df[feature_cols].apply(pd.to_numeric, errors="coerce").fillna(0)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    cluster_ids = sorted(df.cluster_id.unique())
    devices = df.device.values

    colors = plt.cm.Set2(np.linspace(0, 1, len(cluster_ids)))

    # ---------------------------------------------------------
    # helper for drawing convex hulls
    # ---------------------------------------------------------
    def draw_hull(points, color):
        if len(points) < 3:
            return
        hull = ConvexHull(points)
        hull_pts = points[hull.vertices]
        plt.fill(
            hull_pts[:, 0], hull_pts[:, 1],
            color=color, alpha=0.18, edgecolor=color, linewidth=1.5
        )

    # =========================================================
    # PCA projection
    # =========================================================
    pca2 = PCA(n_components=2)
    X_pca = pca2.fit_transform(X_scaled)

    plt.figure(figsize=(13, 10))
    for idx, cid in enumerate(cluster_ids):
        mask = df.cluster_id == cid
        pts = X_pca[mask]

        draw_hull(pts, colors[idx])

        plt.scatter(
            pts[:, 0], pts[:, 1],
            s=160, color=colors[idx], edgecolor="black",
            linewidth=0.8, label=f"C{cid}", alpha=0.85
        )

    for i, dev in enumerate(devices):
        plt.text(
            X_pca[i, 0], X_pca[i, 1],
            dev, fontsize=9, ha="center", va="center"
        )

    plt.title(f"{title_prefix} PCA Projection (2D)", fontsize=20)
    plt.xlabel("PCA component 1", fontsize=16)
    plt.ylabel("PCA component 2", fontsize=16)
    plt.grid(alpha=0.25)
    plt.legend(fontsize=14)
    plt.tight_layout()
    plt.savefig("cluster_embedding_pca2d_beautified.pdf", dpi=300)
    plt.show()


    # =========================================================
    # UMAP projection
    # =========================================================
    reducer = umap.UMAP(
        n_neighbors=10,
        min_dist=0.15,
        random_state=42
    )
    X_umap = reducer.fit_transform(X_scaled)

    plt.figure(figsize=(13, 10))
    for idx, cid in enumerate(cluster_ids):
        mask = df.cluster_id == cid
        pts = X_umap[mask]

        draw_hull(pts, colors[idx])

        plt.scatter(
            pts[:, 0], pts[:, 1],
            s=160, color=colors[idx], edgecolor="black",
            linewidth=0.8, label=f"C{cid}", alpha=0.85
        )

    for i, dev in enumerate(devices):
        plt.text(
            X_umap[i, 0], X_umap[i, 1],
            dev, fontsize=9, ha="center", va="center"
        )

    plt.title(f"{title_prefix} UMAP Projection (2D)", fontsize=20)
    plt.xlabel("UMAP dimension 1", fontsize=16)
    plt.ylabel("UMAP dimension 2", fontsize=16)
    plt.grid(alpha=0.25)
    plt.legend(fontsize=14)
    plt.tight_layout()
    plt.savefig("cluster_embedding_umap2d_beautified.pdf", dpi=300)
    plt.show()

    print("Saved beautified PCA and UMAP diagrams.")


def plot_category_performance(df_clusters, perf_csv=PERF_PATH):
    """
    Dumbbell plot showing idle vs active F1 per-device,
    grouped by category instead of cluster.
    """

    # Load performance table
    perf_raw = pd.read_csv(perf_csv)
    perf = perf_raw.loc[:, ~perf_raw.columns.str.contains("^Unnamed")]

    # Cleanup % symbols
    for col in perf.columns:
        if perf[col].dtype == object:
            perf[col] = perf[col].str.replace("%", "")
    perf = perf.apply(pd.to_numeric, errors="ignore")

    # Merge
    df = pd.merge(df_clusters, perf, on="device", how="inner")
    df["Difference"] = df["f1_idle"] - df["f1_active"]

    # Sorted category labels
    categories = sorted(df["category"].unique())
    df["cat_label"] = df["category"]

    # Sort: first by category, then by difference inside each group
    df_sorted = df.sort_values(
        ["category", "Difference"],
        ascending=[True, False]
    ).reset_index(drop=True)

    devices = df_sorted["device"].values
    x = np.arange(len(devices))

    y_idle = df_sorted["f1_idle"].values
    y_active = df_sorted["f1_active"].values

    # Plot
    fig, ax = plt.subplots(figsize=(22, 10))

    bg_colors = ["#ffffff", "#f2f2f2"]
    groups = df_sorted.groupby("category")

    # Background category blocks
    for i, (cat, group) in enumerate(groups):
        idxs = group.index
        start, end = idxs[0] - 0.5, idxs[-1] + 0.5
        ax.axvspan(start, end, color=bg_colors[i % 2], alpha=1.0)

        mid = (start + end) / 2
        ax.text(
            mid, 107, cat,
            ha="center", fontsize=22, fontweight="bold"
        )

    # Dumbbells
    ax.vlines(x, y_active, y_idle, color="#4d4d4d", linewidth=2)
    ax.scatter(x, y_idle, s=130, color="#bdbdbd", label="Idle Baseline")
    ax.scatter(x, y_active, s=130, color="#d62728", label="Active (Masked)")

    # Styling
    ax.set_ylim(40, 110)
    ax.set_ylabel("F1 Score (%)", fontsize=26)
    ax.set_xticks(x)
    ax.set_xticklabels(devices, rotation=90, fontsize=18)

    ax.grid(axis="y", linestyle="--", alpha=0.5)
    sns.despine()
    ax.legend(fontsize=22)

    plt.tight_layout()
    plt.savefig("category_f1_dumbbell.pdf", dpi=300)
    plt.show()

    return df_sorted



def plot_category_embedding(df, feature_cols=None, title_prefix="Category"):
    """
    Visualize device categories using PCA and UMAP.
    Each category is plotted with a convex hull + labeled points.
    """

    df = df.copy()

    # ---------------------------------------------------------
    # 1. Select numeric features
    # ---------------------------------------------------------
    if feature_cols is None:
        feature_cols = [
            c for c in df.columns
            if c not in ["device", "category", "cluster_id"]
        ]

    X = df[feature_cols].apply(pd.to_numeric, errors="coerce").fillna(0)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    categories = sorted(df["category"].unique())
    devices = df["device"].values

    # softer color palette
    palette = sns.color_palette("Set2", len(categories))
    color_map = {cat: palette[i] for i, cat in enumerate(categories)}

    # ---------------------------------------------------------
    # helper for convex hull
    # ---------------------------------------------------------
    def draw_hull(points, color):
        if len(points) < 3:
            return
        hull = ConvexHull(points)
        pts = points[hull.vertices]
        plt.fill(
            pts[:, 0], pts[:, 1],
            color=color, alpha=0.18,
            edgecolor=color, linewidth=1.5
        )

    # =========================================================
    # PCA Projection
    # =========================================================
    pca2 = PCA(n_components=2)
    X_pca = pca2.fit_transform(X_scaled)

    plt.figure(figsize=(13, 10))
    for cat in categories:
        mask = df["category"] == cat
        pts = X_pca[mask]

        draw_hull(pts, color_map[cat])

        plt.scatter(
            pts[:, 0], pts[:, 1],
            s=160, color=color_map[cat],
            edgecolor="black", linewidth=0.8,
            alpha=0.85, label=cat
        )

    for i, dev in enumerate(devices):
        plt.text(X_pca[i, 0], X_pca[i, 1], dev, fontsize=9,
                 ha="center", va="center")

    plt.title(f"{title_prefix} PCA Projection (2D)", fontsize=20)
    plt.xlabel("PCA component 1", fontsize=16)
    plt.ylabel("PCA component 2", fontsize=16)
    plt.grid(alpha=0.25)
    plt.legend(fontsize=14, title="Category")
    plt.tight_layout()
    plt.savefig("category_embedding_pca2d.pdf", dpi=300)
    plt.show()

    # =========================================================
    # UMAP Projection
    # =========================================================
    reducer = umap.UMAP(
        n_neighbors=10,
        min_dist=0.15,
        random_state=42
    )
    X_umap = reducer.fit_transform(X_scaled)

    plt.figure(figsize=(13, 10))
    for cat in categories:
        mask = df["category"] == cat
        pts = X_umap[mask]

        draw_hull(pts, color_map[cat])

        plt.scatter(
            pts[:, 0], pts[:, 1],
            s=160, color=color_map[cat],
            edgecolor="black", linewidth=0.8,
            alpha=0.85, label=cat
        )

    for i, dev in enumerate(devices):
        plt.text(X_umap[i, 0], X_umap[i, 1], dev, fontsize=9,
                 ha="center", va="center")

    plt.title(f"{title_prefix} UMAP Projection (2D)", fontsize=20)
    plt.xlabel("UMAP-1", fontsize=16)
    plt.ylabel("UMAP-2", fontsize=16)
    plt.grid(alpha=0.25)
    plt.legend(fontsize=14, title="Category")
    plt.tight_layout()
    plt.savefig("category_embedding_umap2d.pdf", dpi=300)
    plt.show()

    print("Saved beautified category PCA and UMAP diagrams.")
