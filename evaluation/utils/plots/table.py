import jsonpickle
import matplotlib.pyplot as plt
import numpy as np


def plot(entries_files, metric, stats, colors, colLabels, rowLabels, kwds, output_file):
    fig = plt.figure(layout='constrained', figsize=(5, 4), dpi=300)
    # fig = plt.figure(layout='tight', figsize=(4, 4), dpi=300)
    ax = fig.add_subplot(111)
    ax.set_title(kwds['title'], fontsize=10)
    ax.set_ylabel(kwds['ylabel'])

    data = []
    for i, gen_ego in enumerate(colLabels):
        col_data = []
        x_start = i / len(colLabels)
        x_end = (i+1) / len(colLabels)
        x = np.linspace(x_start, x_end, len(rowLabels) + 1)
        width = (x[1]-x[0])*.5
        j = 1
        for test_ego in rowLabels:
            if test_ego == gen_ego:
                col_data.append('')
                continue

            with open(entries_files[gen_ego, test_ego], 'r') as f:
                comparison_trials = jsonpickle.decode(f.read())
            metric_trials = tuple(metric(trial) for trial in comparison_trials)
            cell_data = tuple(stat(metric_trials) for stat in stats)
            col_data.append(cell_data)

            # box plot of the cell data
            bplot = ax.boxplot(metric_trials, positions=[x[j]], widths=[width], patch_artist=True)
            for patch in bplot['boxes']:
                patch.set(facecolor=colors[test_ego])
            for median in bplot['medians']:
                median.set_color('black')

            j += 1

        data.append(col_data)


    data_text = [
        [', '.join(f'{int(d)}' for d in cell_data) for cell_data in col]
        for col in data
    ]
    table = ax.table(cellText=np.transpose(np.array(data_text)),
                    rowLabels=rowLabels,
                    colLabels=colLabels,
                    rowColours=tuple(colors[l] for l in rowLabels),
                    colColours=tuple(colors[l] for l in colLabels),
                    alpha=kwds['fill_alpha'],
                    )
    table[1, 0].get_text().set_text('Min, Median, Max')
    # Set font size for all cells
    table.auto_set_font_size(False)  # Disable automatic font size
    for key, cell in table.get_celld().items():
        cell.set_fontsize(7)

    plt.xticks([])
    ax.set_xlim([0, 1])
    fig.subplots_adjust(left=.2, bottom=.2)
    fig.savefig(output_file)
    