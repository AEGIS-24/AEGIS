from matplotlib.font_manager import FontProperties
import matplotlib.pyplot as plt
from matplotlib.ticker import FuncFormatter
import pandas as pd
import sys
from collections import defaultdict
import seaborn as sns
import re


def extract_scores(records, start_index):
    return [float(records[i]) for i in range(start_index, len(records), 2)]


def calculate_average(scores):
    return sum(scores) / len(scores) if scores else 0.0


def calculate_percentage_difference(avg1, avg2):
    res = ((avg1 - avg2) / avg2) * 100 if avg2 != 0 else 0.0
    return res


cleaned_data = defaultdict(list)

df = pd.DataFrame()


def main():
    if len(sys.argv) < 2:
        print("Usage: python getrecords.py <path_to_file>")
        sys.exit(1)

    lines = []
    for file_path in sys.argv[1:]:
        with open(file_path, 'r') as f:
            lines.extend(f.readlines())

    # records = defaultdict(list)
    records = defaultdict(lambda: defaultdict(lambda: defaultdict(list)))

    for line in lines:
        line = line.strip()
        if "bpf script enabled" in line:
            idx = "enabled"
        elif "bpf script disabled" in line:
            idx = "disabled"
        elif "Running option:" in line:
            opt = line.split(':')[-1].split('(')[0].strip()
        elif "iPerf" in line:
            item = "iperf3"
        elif "Memcached" in line:
            item = "memcached"
        elif "Redis" in line:
            item = "redis"
        elif "PostgreSQL" in line:
            item = "postgres"
        elif "nginx" in line:
            item = "nginx"
        elif "Apache HTTP Server" in line:
            item = "httpd"
        elif "Average:" in line:
            r = line.split(':')[-1].strip().split()[0].strip()
            if float(r) < 1:
                continue
            records[idx][opt][item].append(float(r))

    data = []
    for idx in records:
        for opt in ['low', 'mid', 'high']:
            for item in ['nginx', 'iperf3', 'memcached', 'postgres', 'httpd', 'redis']:
                if records[idx][opt][item]:
                    avg_score = sum(records[idx][opt][item]) / \
                        len(records[idx][opt][item])
                    data.append({'CVE': idx, 'Option': opt,
                                'Item': item, 'Score': avg_score})

    df1 = pd.DataFrame(data)
    analyze_and_visualize(df1)


def analyze_and_visualize(df1):
    grouped = df1.groupby(['CVE', 'Option', 'Item'])[
        'Score'].mean().reset_index()

    items = df1['Item'].unique()
    options = df1['Option'].unique()

    for item in items:
        fig, axes = plt.subplots(nrows=1, ncols=len(
            options), figsize=(18, 6))
        fig.suptitle(f'Performance Difference for {
                     item} by Option Compared to Disabled')

        for i, option in enumerate(options):
            item_option_data = grouped[(grouped['Item'] == item) & (
                grouped['Option'] == option)]
            baseline = item_option_data[item_option_data['CVE'] ==
                                        'disabled']['Score'].values[0] if 'disabled' in item_option_data['CVE'].values else None

            if baseline is not None:
                comparison_data = item_option_data[item_option_data['CVE'] != 'disabled']
                comparison_data['Percentage Difference'] = (
                    comparison_data['Score'] - baseline) / baseline * 100

                sns.barplot(data=comparison_data, x='CVE',
                            y='Percentage Difference', ax=axes[i])
                axes[i].set_title(f'Option {option}')
                axes[i].axhline(0, color='gray', linestyle='--')
                axes[i].set_xlabel('CVE Identifier')
                axes[i].set_ylabel('Percentage Difference (%)')

        plt.tight_layout(rect=[0, 0.03, 1, 0.95])
        # plt.show()

    # print(grouped[grouped['CVE'] == "disabled"])

    for item in items:
        fig, axes = plt.subplots(nrows=1, ncols=len(options), figsize=(18, 6))
        fig.suptitle(f'Overall Performance Distribution for {
                     item} Compared to Disabled')

        for i, option in enumerate(options):
            item_option_data = grouped[(grouped['Item'] == item) & (
                grouped['Option'] == option)]
            baseline_data = grouped[(grouped['Item'] == item) & (
                grouped['Option'] == option) & (grouped['CVE'] == 'disabled')]

            if not baseline_data.empty:
                baseline = baseline_data['Score'].mean()
                if not item_option_data.empty:
                    comparison_data = item_option_data.copy()
                    comparison_data['Normalized Score'] = (
                        comparison_data['Score'] - baseline) / baseline * 100
                    sns.violinplot(data=comparison_data,
                                   y='Normalized Score', ax=axes[i], cut=0)
                    axes[i].set_title(f'Option {option}')
                    axes[i].set_ylabel('Percentage Difference (%)')
                else:
                    axes[i].set_title(f'Option {option} (No Data)')
            else:
                axes[i].set_title(f'Option {option} (No Baseline)')

        plt.tight_layout(rect=[0, 0.03, 1, 0.95])
        # plt.show()


if __name__ == "__main__":
    main()
