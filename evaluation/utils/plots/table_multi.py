import jsonpickle
import matplotlib.pyplot as plt
import numpy as np


def plot(entries_files, stats, colors, rowLabels, kwds, output_file):
    fig = plt.figure(layout='constrained', figsize=(5, 4), dpi=300)
    # fig = plt.figure(layout='tight', figsize=(4, 4), dpi=300)
    ax = fig.add_subplot(111)
    # if 'title' in kwds:
    #     ax.set_title(kwds['title'], fontsize=10)
    ax.spines['top'].set_color('none')
    ax.spines['bottom'].set_color('none')
    ax.spines['left'].set_color('none')
    ax.spines['right'].set_color('none')
    ax.tick_params(labelcolor='w', top=False, bottom=False, left=False, right=False)        

    with open(entries_files[0], 'r') as f:
        entries = jsonpickle.decode(f.read())
        number_of_entries = len(entries)

    # subplots = []
    # for i, entry in enumerate(entries):
    #     subplot = fig.add_subplot(number_of_entries, i+1, 1)
    #     subplot.set_ylabel(entry)
    #     subplot.set_xlim([0, 1])
    #     subplots.append(subplot)

    
    fig, subplots = plt.subplots(1, len(entries), figsize=(5, 4))
    for ax in subplots:
        ax.set_xlim([0, 1])
        ax.set_xticks([])

    data = []
    for i, (row_label, entries_file) in enumerate(zip(rowLabels, entries_files)):
        with open(entries_file, 'r') as f:
            entries = jsonpickle.decode(f.read())
        col_data = []
        offset = np.linspace(0, 1, len(entries_files)+2)
        for j, (entry, trials) in enumerate(entries.items()):
            cell_data = tuple(stat(trials) for stat in stats)
            col_data.append(cell_data)

            # box plot of the cell data
            x_base = j
            width = 1 / (len(entries_files) + 1)
            bplot = subplots[j].boxplot(trials, positions=[j+offset[i+1]], widths=[width], patch_artist=True)
            for patch in bplot['boxes']:
                patch.set(facecolor=colors[i])
            for median in bplot['medians']:
                median.set_color('black')

        data.append(col_data)


    data_text = [
        [', '.join(f'{int(d)}' for d in cell_data) for cell_data in col]
        for col in data
    ]
    table = plt.table(cellText=np.transpose(np.array(data_text)),
                    rowLabels=rowLabels,
                    colLabels=tuple(entries.keys()),
                    rowColours=colors,
                    alpha=kwds['fill_alpha'],
                    loc='bottom'
                    )
    table[1, 0].get_text().set_text('Min, Median, Max')
    # Set font size for all cells
    table.auto_set_font_size(False)  # Disable automatic font size
    for key, cell in table.get_celld().items():
        cell.set_fontsize(7)

    plt.xticks([])
    # ax.set_xlim([0, number_of_entries])
    fig.subplots_adjust(left=.2, bottom=.2)
    fig.savefig(output_file)
    