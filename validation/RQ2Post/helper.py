###############################################################
#   Masking Behaviour Clustering (Performance Pattern Only)
###############################################################

import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
from sklearn.cluster import KMeans
from sklearn.metrics import silhouette_score
import matplotlib.pyplot as plt
import seaborn as sns
from scipy.spatial import ConvexHull
from matplotlib.patches import Ellipse
import matplotlib.transforms as transforms
import matplotlib.patheffects as pe
from adjustText import adjust_text


def build_pattern_feature_table(perf_csv):
    perf = pd.read_csv(perf_csv)

    # clean percentage strings
    for col in ["f1_idle", "f1_active"]:
        if perf[col].dtype == object:
            perf[col] = perf[col].str.replace("%", "").astype(float)

    # new behaviour features
    perf["drop_abs"] = perf["f1_idle"] - perf["f1_active"]
    perf["drop_rel"] = perf["drop_abs"] / perf["f1_idle"]
    
    # idle and active rank
    perf["rank_idle"] = perf["f1_idle"].rank(ascending=False)
    perf["rank_active"] = perf["f1_active"].rank(ascending=False)
    perf["rank_shift"] = perf["rank_active"] - perf["rank_idle"]

  
    pattern_feats = [
        "f1_idle",
        "f1_active",
        "drop_abs",
        "drop_rel",
        "rank_shift"
    ]

    df_pat = perf[["device"] + pattern_feats].copy()
    return df_pat

###############################################################
# Step one: K Selection from pattern features (Elbow + Silhouette)
###############################################################

def pattern_k_selection(df_pat, k_min=2, k_max=12):
    X = df_pat.drop(columns=["device"]).fillna(0)
    X_scaled = StandardScaler().fit_transform(X)

    pca = PCA(n_components=0.99)
    X_pca = pca.fit_transform(X_scaled)

    Ks = list(range(k_min, k_max + 1))
    inertias = []
    silhouettes = []

    for k in Ks:
        km = KMeans(n_clusters=k, n_init=30, random_state=42)
        labels = km.fit_predict(X_pca)
        inertias.append(km.inertia_)
        silhouettes.append(silhouette_score(X_pca, labels))

    fig, ax1 = plt.subplots(figsize=(12, 6))

    ax1.set_xlabel("Number of Clusters (k)")
    ax1.set_ylabel("Inertia (Elbow)", color="tab:blue")
    ax1.plot(Ks, inertias, marker="o", color="tab:blue")
    ax1.tick_params(axis="y", labelcolor="tab:blue")
    ax1.grid(True, alpha=0.4)

    ax2 = ax1.twinx()
    ax2.set_ylabel("Silhouette Score", color="tab:red")
    ax2.plot(Ks, silhouettes, marker="s", linestyle="--", color="tab:red")
    ax2.tick_params(axis="y", labelcolor="tab:red")

    plt.title("Optimal K Selection (Masking Behaviour)")
    plt.tight_layout()
    plt.show()

    best_k = Ks[np.argmax(silhouettes)]
    print("Best K from silhouette", best_k)
    return best_k


###############################################################
# Step two: Final clustering of pattern features
###############################################################

def run_pattern_clustering(df_pat, k):
    X = df_pat.drop(columns=["device"]).fillna(0)
    X_scaled = StandardScaler().fit_transform(X)

    pca = PCA(n_components=0.99)
    X_pca = pca.fit_transform(X_scaled)

    km = KMeans(n_clusters=k, n_init=50, random_state=42)
    labels = km.fit_predict(X_pca)

    df_pat["mask_cluster"] = labels
    return df_pat, X_pca

###############################################################
# Step three: PCA and UMAP embedding for behaviour clusters
###############################################################

def draw_confidence_ellipse_correct(x, y, ax, n_std=2.0, facecolor='none', **kwargs):
    if len(x) < 2:
        return

    cov = np.cov(x, y)
    vals, vecs = np.linalg.eigh(cov)

    # Sort eigenvectors by eigenvalue
    order = vals.argsort()[::-1]
    vals = vals[order]
    vecs = vecs[:, order]

    theta = np.degrees(np.arctan2(*vecs[:, 0][::-1]))

    width, height = 2 * n_std * np.sqrt(vals)

    ellipse = Ellipse(
        (np.mean(x), np.mean(y)),
        width=width,
        height=height,
        angle=theta,
        facecolor=facecolor,
        **kwargs
    )
    ax.add_patch(ellipse)

def plot_masking_pca(df_pat, X_pca):
    # Your custom 6-color palette
    color_map = {
        0: "#34669a",
        1: "#86bad4",
        2: "#f5b783",
        3: "#e0795f",
    }

    fig, ax = plt.subplots(figsize=(14, 11))

    # 1. Confidence ellipses
    for cid in sorted(df_pat.mask_cluster.unique()):
        pts = X_pca[df_pat.mask_cluster == cid]
        draw_confidence_ellipse_correct(
            pts[:, 0], pts[:, 1], ax,
            n_std=2.0,
            facecolor=color_map[cid],
            alpha=0.15,
            edgecolor=color_map[cid],
            linewidth=1.4
        )

    # 2. Points
    for cid in sorted(df_pat.mask_cluster.unique()):
        pts = X_pca[df_pat.mask_cluster == cid]
        ax.scatter(
            pts[:, 0], pts[:, 1],
            s=200,
            color=color_map[cid],
            edgecolor="white",
            linewidth=1.3,
            label=f"M{cid}",
            alpha=0.95,
            zorder=3
        )

    # 3. Device labels
    texts = []
    for i, row in df_pat.iterrows():
        txt = ax.text(
            X_pca[i, 0],
            X_pca[i, 1],
            row["device"],
            fontsize=20,
            color="#333333",
            path_effects=[pe.withStroke(linewidth=2.5, foreground="white", alpha=0.8)]
        )
        texts.append(txt)

    adjust_text(
        texts,
        arrowprops=dict(arrowstyle="-", color="gray", alpha=0.35),
        force_text=0.35,
        expand_points=(1.3, 1.3),
        expand_text=(1.2, 1.2)
    )

    # 4. Styling
    # ax.set_title("Masking Behaviour PCA Projection", fontsize=22, pad=18)
    ax.set_xlabel("PCA Component 1", fontsize=28)
    ax.set_ylabel("PCA Component 2", fontsize=28)
    ax.grid(True, linestyle=":", alpha=0.35)
    ax.tick_params(axis='both', which='major', labelsize=24)

    legend = ax.legend(fontsize=28, frameon=True)
    legend.get_frame().set_alpha(0.92)

    plt.tight_layout()
    plt.savefig("masking_pca_ellipse.pdf", dpi=350)
    plt.show()



###############################################################
# Step four: Post verification (Standardised for visibility)
###############################################################

def verify_mask_groups(df_pat, full_features_csv):
    df_feats = pd.read_csv(full_features_csv)

    df_merged = pd.merge(
        df_feats,
        df_pat[["device", "mask_cluster"]],
        on="device",
        how="inner"
    )

    feat_cols = [
        c for c in df_merged.columns
        if c not in ["device", "mask_cluster"]
    ]

    # numeric only
    X = df_merged[feat_cols].apply(pd.to_numeric, errors="coerce").fillna(0)

    # *** place the filtering right here ***
    # remove features with almost no variation across devices
    X = X.loc[:, X.std() > 1e-6]

    # now compute z score
    X_z = (X - X.mean()) / (X.std() + 1e-9)

    X_z["mask_cluster"] = df_merged["mask_cluster"].values

    cluster_profiles = X_z.groupby("mask_cluster").mean()

    plt.figure(figsize=(16, 14))
    sns.heatmap(
        cluster_profiles.T,
        cmap="vlag",
        center=0,
        linewidths=0.2
    )
    plt.title("Standardised Feature Structure inside Masking Behaviour Groups")
    plt.tight_layout()
    plt.show()

    return cluster_profiles


import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.colors import LinearSegmentedColormap

def verify_mask_groups_compact(df_pat, full_features_csv, top_n=25):
    
    # 1. Load and Merge Data
    df_feats = pd.read_csv(full_features_csv)
    df_merged = pd.merge(df_feats, df_pat[["device", "mask_cluster"]], on="device", how="inner")

    # 2. Pre-processing & Z-Score
    feat_cols = [c for c in df_merged.columns if c not in ["device", "mask_cluster"]]
    X = df_merged[feat_cols].apply(pd.to_numeric, errors="coerce").fillna(0)
    X = X.loc[:, X.std() > 1e-6]
    X_z = (X - X.mean()) / (X.std() + 1e-9)
    X_z["mask_cluster"] = df_merged["mask_cluster"]

    # 3. Group by Cluster
    cluster_profiles = X_z.groupby("mask_cluster").mean().T

    # 4. Compact Feature Names (Merge Idle/Active)
    compact_rows = []
    base_features = sorted(list(set([f.replace('_idle', '').replace('_active', '') for f in cluster_profiles.index])))

    for base_feat in base_features:
        idle_feat = f"{base_feat}_idle"
        active_feat = f"{base_feat}_active"
        row_data = {}
        if idle_feat in cluster_profiles.index and active_feat in cluster_profiles.index:
            for cid in cluster_profiles.columns:
                row_data[(cid, 'Idle')] = cluster_profiles.loc[idle_feat, cid]
                row_data[(cid, 'Active')] = cluster_profiles.loc[active_feat, cid]
            row_df = pd.DataFrame([row_data], index=[f"{base_feat} (I/A)"])
            compact_rows.append(row_df)

    if not compact_rows:
        return None
        
    compact_df = pd.concat(compact_rows)
    compact_df.columns = pd.MultiIndex.from_tuples(compact_df.columns, names=['Mask Group', 'State'])
    compact_df = compact_df.sort_index(axis=1, level=[0, 1], ascending=[True, False]) 

    # 5. Filter Top Features
    compact_df["variation"] = compact_df.std(axis=1)
    top_features_df = compact_df.sort_values("variation", ascending=False).head(top_n)
    plot_data = top_features_df.drop(columns=["variation"])

    # 6. Plotting - Custom Color & Size
    plt.figure(figsize=(16, len(plot_data) * 0.3 + 3)) 

    # --- CUSTOM COLORMAP ---
    # Low (Blue) -> Zero (White) -> High (Your Orange #f3a361)
    # Using a soft blue to match the soft orange
    colors = ["#34669a", "#ffffff", "#e0795f"] 
    cmap = LinearSegmentedColormap.from_list("custom_blue_orange", colors, N=256)

    ax = sns.heatmap(
        plot_data,
        cmap=cmap,
        center=0,
        linewidths=0.5,
        linecolor='white',
        cbar_kws={
            'label': 'Z-Score (Deviation)', 
            'shrink': 0.8, 
            'aspect': 25,
            'pad': 0.03
        }
    )

    # 7. Customize Labels - BIG SIZE, NO BOLD

    # Colorbar
    cbar = ax.collections[0].colorbar
    cbar.ax.tick_params(labelsize=20) # Big numbers
    cbar.set_label('Feature Deviation (Z-Score)', size=28, fontweight='normal') # Big Label

    # Y-Axis (Feature Names)
    clean_y_labels = [label.replace(' (I/A)', '').replace('_', ' ') for label in plot_data.index]
    ax.set_yticklabels(clean_y_labels, fontsize=28, fontweight='normal', rotation=0)
    
    # X-Axis Bottom (States: I/A)
    states = [col[1] for col in plot_data.columns] 
    ax.set_xticklabels(states, rotation=0, fontsize=28, fontweight='normal')
    ax.set_xlabel("", fontsize=0)

    # X-Axis Top (Groups: M0, M1...)
    ax_top = ax.twiny()
    ax_top.set_xlim(ax.get_xlim())
    num_groups = len(plot_data.columns) // 2
    group_centers = [i * 2 + 1 for i in range(num_groups)]
    group_labels = [f"M{col[0]}" for col in plot_data.columns[::2]]
    
    ax_top.set_xticks(group_centers)
    # SUPER BIG group labels, no bold
    ax_top.set_xticklabels(group_labels, fontsize=26, fontweight='normal') 
    ax_top.tick_params(length=0) 

    # Separation Lines
    for i in range(2, len(plot_data.columns), 2):
        ax.axvline(i, color='white', linewidth=6) 

    # Title
    # plt.title(f"Discriminative Features Structure", fontsize=30, pad=45, fontweight='normal')

    plt.tight_layout()
    plt.savefig("heatmap.pdf", dpi=300, bbox_inches='tight')
    plt.show()

    return plot_data


###############################################################
#   Masking Behaviour Dumbbell Plot
###############################################################

def plot_masking_performance(df_pat, perf_csv):
    perf = pd.read_csv(perf_csv)

    for col in ["f1_idle", "f1_active"]:
        if perf[col].dtype == object:
            perf[col] = perf[col].str.replace("%", "").astype(float)

    df = pd.merge(df_pat[["device", "mask_cluster"]], perf, on="device", how="inner")

    if df.empty:
        print("Merge failed no matching device names")
        return

    df["Difference"] = df["f1_idle"] - df["f1_active"]

    cluster_map = {cid: f"M{cid}" for cid in sorted(df.mask_cluster.unique())}
    df["Cluster_Label"] = df["mask_cluster"].map(cluster_map)

    df_sorted = df.sort_values(["mask_cluster", "Difference"], ascending=[True, False]).reset_index(drop=True)

    devices = df_sorted["device"].values
    x = np.arange(len(devices))
    y_idle = df_sorted["f1_idle"].values
    y_active = df_sorted["f1_active"].values

    fig, ax = plt.subplots(figsize=(20, 9))

    bg_colors = ["#ffffff", "#f2f2f2"]
    groups = df_sorted.groupby("mask_cluster")

    for i, (cid, group) in enumerate(groups):
        idxs = group.index
        start, end = idxs[0] - 0.5, idxs[-1] + 0.5
        ax.axvspan(start, end, facecolor=bg_colors[i % 2], alpha=1.0, zorder=0)

        mid = (start + end) / 2
        ax.text(
            mid,
            102,
            f"M{cid}",
            ha="center",
            fontsize=20,
            weight="bold",
            color="#333"
        )

    ax.vlines(x, y_active, y_idle, color="#6c6c6c", linewidth=2.2, alpha=0.7, zorder=1)

    ax.scatter(x, y_idle, s=150, color="#bdbdbd", edgecolors="#555555", label="Idle")
    ax.scatter(x, y_active, s=150, color="#e53935", edgecolors="#7f0000", label="Active")

    ax.set_ylim(40, 110)
    ax.set_ylabel("F1 Score (%)", fontsize=22)
    ax.set_xticks(x)
    ax.set_xticklabels(devices, rotation=90, fontsize=15)
    ax.tick_params(axis="y", labelsize=20)

    ax.legend(loc="lower left", fontsize=18)
    ax.grid(axis="y", linestyle="--", alpha=0.45)
    sns.despine()

    plt.tight_layout()
    plt.savefig("masking_dumbbell_performance.pdf", dpi=300)
    plt.show()

    return df_sorted

import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns

def plot_masking_performance_final(df_pat, perf_csv):
    # 1. Data Prep
    perf = pd.read_csv(perf_csv)
    for col in ["f1_idle", "f1_active"]:
        if perf[col].dtype == object:
            perf[col] = perf[col].str.replace("%", "").astype(float)
            
    df = pd.merge(df_pat[["device", "mask_cluster"]], perf, on="device", how="inner")
    
    if df.empty:
        print("Merge failed.")
        return

    df["Difference"] = df["f1_idle"] - df["f1_active"]
    df_sorted = df.sort_values(["mask_cluster", "Difference"], ascending=[True, False]).reset_index(drop=True)

    devices = df_sorted["device"].values
    x = np.arange(len(devices))
    y_idle = df_sorted["f1_idle"].values
    y_active = df_sorted["f1_active"].values

    # 2. Setup Plot
    fig, ax = plt.subplots(figsize=(20, 10))

    # Background Colors
    bg_colors = ["#f8f9fa", "#e9ecef"] 
    
    groups = df_sorted.groupby("mask_cluster")
    for i, (cid, group) in enumerate(groups):
        idxs = group.index
        start, end = idxs[0] - 0.5, idxs[-1] + 0.5
        ax.axvspan(start, end, facecolor=bg_colors[i % 2], alpha=1.0, zorder=0)

        mid = (start + end) / 2
        ax.text(mid, 103, f"M{cid}", ha="center", fontsize=28, weight="bold", color="#2c3e50")

    # Lines
    ax.vlines(x, y_active, y_idle, color="#505050", linewidth=2.5, alpha=0.6, zorder=1)

    # Points (Dual Coding: Circle + Triangle)
    ax.scatter(x, y_idle, s=160, marker='o', color="#bdc3c7", edgecolors="#7f8c8d", 
               linewidth=1.5, label="Idle Baseline", zorder=2)

    ax.scatter(x, y_active, s=180, marker='^', color="#e74c3c", edgecolors="#c0392b", 
               linewidth=1.5, label="Active (Masked)", zorder=3)

    # 3. Styling - The Fix for Y-Axis
    ax.set_yticks(np.arange(40, 101, 10)) 
    ax.set_ylim(35, 108) 
    
    ax.set_ylabel("Detection F1 Score (%)", fontsize=30, labelpad=15)
    ax.set_xticks(x)
    ax.set_xticklabels(devices, rotation=90, fontsize=28, fontweight='medium')
    ax.tick_params(axis="y", labelsize=28)

    # Grid
    ax.grid(axis="y", linestyle="--", alpha=0.5)
    
    # Legend
    legend = ax.legend(loc="lower left", fontsize=28, frameon=True, framealpha=0.95)
    legend.get_frame().set_edgecolor('#dcdcdc')

    sns.despine(left=True, bottom=False)

    plt.tight_layout()
    plt.savefig("masking_dumbbell_final.pdf", dpi=300)
    plt.show()

    return df_sorted