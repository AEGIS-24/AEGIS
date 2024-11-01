from matplotlib.font_manager import FontProperties
import matplotlib.pyplot as plt
from matplotlib.ticker import FuncFormatter, PercentFormatter
import pandas as pd
import sys
from collections import defaultdict
import seaborn as sns


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

    cnt = 0
    for line in lines:
        line = line.strip()
        cnt += 1
        if "Running bpftrace script" in line:
            idx = line.split('/')[-1].split('#')[0]
            idx += f"_#{cnt}"
        elif "Disable bpftrace scripts" in line:
            idx = "disabled"
        # elif "System Benchmarks Index Score" in line:
            # records[idx].append(float(line.split()[-1]))
        elif "Running option:" in line:
            opt = line.split(':')[-1].split('(')[0].strip()
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
                # print("Invalid score:", r)
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
    # df1.to_csv("df1.csv")
    # print(df1[df1['CVE'] == 'disabled'])
    analyze_and_visualize(df1)
    analyze_and_print(df1)


def analyze_and_visualize(df1):
    grouped = df1.groupby(['CVE', 'Option', 'Item'])[
        'Score'].mean().reset_index()

    items = df1['Item'].unique()
    options = df1['Option'].unique()

    for item in items:
        if len(options) == 1:
            fig, axes = plt.subplots(nrows=1, ncols=1, figsize=(9, 6))
            axes = [axes]  # Convert single Axes object to a list
        else:
            fig, axes = plt.subplots(
                nrows=1, ncols=len(options), figsize=(18, 6))

        # for item in ['nginx', 'iperf3', 'memcached', 'postgres', 'httpd', 'redis']:

        namemap = {'nginx': 'Nginx',
                   'iperf3': 'iPerf',
                   'memcached': 'Memcached',
                   'postgres': 'PostgreSQL',
                   'httpd': 'Apache',
                   'redis': 'Redis',
                   }

        # fig.suptitle(f'Overhead Distribution for {namemap[item]}', fontsize=16)

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
                                   y='Normalized Score', ax=axes[i], cut=0, common_norm=True)
                    # axes[i].set_title(f'Option {option}')
                    axes[i].set_ylabel('', fontsize=0)
                    axes[i].yaxis.set_major_formatter(
                        FuncFormatter(lambda x, pos: f'{x:.1f}%'))

                    axes[i].tick_params(
                        axis='both', which='major', labelsize=28)
                    axes[i].tick_params(
                        axis='both', which='minor', labelsize=28)
                else:
                    axes[i].set_title(f'Option {option} (No Data)')
            else:
                axes[i].set_title(f'Option {option} (No Baseline)')

        plt.tight_layout()

        # Save each figure as a PDF
        fig_filename = f"pdf/{namemap[item]}.pdf"
        plt.savefig(fig_filename, format='pdf')
        plt.show()


def analyze_and_print(df1):
    grouped = df1.groupby(['CVE', 'Option', 'Item'])[
        'Score'].mean().reset_index()

    items = df1['Item'].unique()
    options = df1['Option'].unique()

    # Collect detailed comparison data for each item
    for item in items:
        for option in options:
            item_option_data = grouped[(grouped['Item'] == item) & (
                grouped['Option'] == option)]
            baseline_data = grouped[(grouped['Item'] == item) & (
                grouped['Option'] == option) & (grouped['CVE'] == 'disabled')]

            if not baseline_data.empty and not item_option_data.empty:
                baseline = baseline_data['Score'].mean()
                comparison_data = item_option_data.copy()
                comparison_data['Normalized Score'] = (
                    comparison_data['Score'] - baseline) / baseline * 100
                # Print detailed distribution of comparison_data
                print(f"Data Distribution for {item}")
                print(f"  Count: {len(comparison_data)}")
                print(f"  Mean Normalized Score: {
                      comparison_data['Normalized Score'].mean():.2f}")
                print(f"  Min Normalized Score: {
                      comparison_data['Normalized Score'].min():.2f}")
                print(f"  Max Normalized Score: {
                      comparison_data['Normalized Score'].max():.2f}")
                print(f"  Standard Deviation: {
                      comparison_data['Normalized Score'].std(ddof=0):.2f}")

                # Print percentiles
                print(f"  25th Percentile: {
                      comparison_data['Normalized Score'].quantile(0.25):.2f}")
                print(f"  50th Percentile (Median): {
                      comparison_data['Normalized Score'].median():.2f}")
                print(f"  75th Percentile: {
                      comparison_data['Normalized Score'].quantile(0.75):.2f}")
                # print(f"  Normalized Scores: {
                #       comparison_data['Normalized Score'].tolist()}")
                print()  # Blank line for better readability


if __name__ == "__main__":
    main()
