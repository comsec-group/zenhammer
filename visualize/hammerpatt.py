import gc
import os
import pprint as pp
import itertools

from matplotlib.ticker import MaxNLocator

from dramaddr import *
from flip import *
from matplotlib import pyplot as plt
from matplotlib import collections
from matplotlib.lines import Line2D

import seaborn as sns
import pandas as pd
import numpy as np
from operator import attrgetter


def col_green(sstr):
    return f"\033[92m{sstr}\033[0m"


def col_red(sstr):
    return f"\033[91m{sstr}\033[0m"


class AggressorAccessPattern():

    @classmethod
    def from_json(cls, dd):
        if not set(dd.keys()) == set(("frequency", "amplitude", "start_offset", "aggressors")):
            return NotImplemented

        # TODO check that the aggressor list is exported as jsons
        aggr_list = list(map(int, dd['aggressors']))
        return cls(int(dd['frequency']), int(dd['amplitude']), int(dd['start_offset']), aggr_list)

    def __init__(self, period, amplitude, phase, aggr_list, flips=None):
        self.period = period
        self.amplitude = amplitude
        self.phase = phase
        self.aggr_tuple = aggr_list
        self.flips = [] if flips == None else flips

    def __len__(s):
        return len(s.aggr_list)

    def __str__(s):
        flip = col_green("v") if s.flips else col_red("x")

        return f"AggAccPatt[{flip}](period: {s.period}, ampl: {s.amplitude}, phase: {s.phase}, aggr: {s.aggr_tuple})"

    def __repr__(self):
        return self.__str__()

    def map_it(self, addr_map):
        aggr_list = [addr_map[x] for x in self.aggr_tuple]
        return type(self)(aggr_list=aggr_list, **{k: v for k, v in vars(self).items() if k != "aggr_tuple"})

    def attach_flip(self, flip):
        self.flips.append(flip)

    def patt(self):
        return self.aggr_tuple * self.amplitude

    def to_pandas_entry(self, max_period):
        def label(tup):
            return "-".join([f"{x.row}" for x in sorted(tup, key=attrgetter("row"), reverse=True)])

        return {"period": self.period, "frequency": int(max_period / self.period), "amplitude": self.amplitude,
                "phase": self.phase, "flips": True if self.flips else False, "label": label(self.aggr_tuple)}

    # TODO figure out how to draw this in a music-sheet-like format 
    def to_time_plot(self, ax, max_period, lwidth=2):

        GUARD_ROWS = 1

        def rotate(lst, rot, max_period):
            rotate = itertools.islice(itertools.cycle(iter(lst)), len(lst) - rot, 2 * len(lst) - rot)
            extend = itertools.islice(itertools.cycle(rotate), 0, max_period)
            return extend

        def to_lines(serie):
            xlab_serie = list(enumerate(serie))
            # filtered = [x for x,y in xlab_serie if y != None]
            # unique_y = set([y for _,y in xlab_serie if y != None])
            # max_x = max(filtered)
            # min_x = min(filtered)
            # print(f"min_x: {min_x} \t max_x: {max_x}")
            return [[(x, y), (x + 1, y)] for x, y in xlab_serie if y != None]
            # return [[(min_x,y), (max_x,y)] for y in unique_y]

        def yticks_range(serie):
            uniq = set(filter(lambda x: x != None, serie))
            return list(range(min(uniq) - GUARD_ROWS, max(uniq) + GUARD_ROWS + 1))

        def drawable_flips(flips, max_period):
            return [[(0, flip.addr.row), (max_period, flip.addr.row)] for flip in flips]

        def row_tuple_str(tup):
            return "\n".join([f"{x.row}" for x in sorted(tup, key=attrgetter("row"), reverse=True)])

        if not isinstance(self.aggr_tuple[0], DRAMAddr):
            raise Exception("map_it() hasn't been called on this yet!")

        row_idx = lambda x: x.row
        num_rows = len(self.aggr_tuple)
        time_serie = [None] * self.period
        time_serie[0:len(self.patt())] = map(row_idx, self.patt())
        # print(f"period: {self.period}, ampl: {self.amplitude} phase: {self.phase}, max_period: {max_period}")
        time_serie = list(rotate(time_serie, self.phase, max_period))

        lines = to_lines(time_serie)
        yticks = yticks_range(time_serie)
        ylabels = [x if x in [y.row for y in self.aggr_tuple] else None for x in yticks]
        flip_lines = []
        if self.flips:
            flip_lines = drawable_flips(self.flips, max_period)

        lc = collections.LineCollection(lines, linewidths=lwidth)
        lc_flips = collections.LineCollection(flip_lines, linewidths=lwidth * 1.5, color="red")

        # Code drawing the time_plot
        ax.add_collection(lc)
        ax.add_collection(lc_flips)
        ax.set_yticks(yticks)
        ax.set_yticklabels(ylabels, fontsize=5)
        ax.yaxis.set_tick_params(labelsize=5)
        # ax.set_ylabel(ylabel, rotation=0)
        ax.set_ylim(min(yticks), max(yticks))
        ax.grid()


class InstanceList(list):

    def __getitem__(self, key):
        if isinstance(key, int):
            return list.__getitem__(self, key)
        if isinstance(key, str):
            for x in self:
                if x.uid == key:
                    return x


class HammeringPattern():

    @classmethod
    def from_json(cls, ddict):

        if not {"id", "agg_access_patterns", "access_ids", "address_mappings", "base_period", "max_period"}.issubset(
                set(ddict.keys())):
            return NotImplemented
        order = list(map(int, ddict['access_ids']))
        agg_list = list(map(AggressorAccessPattern.from_json, ddict['agg_access_patterns']))
        return cls(ddict['id'], int(ddict['base_period']), int(ddict['max_period']), agg_list, order,
                   ddict['address_mappings'])

    def __init__(self, uid, base_period, max_period, aggr_list, order, mappings):

        def gen_instances(mappings):
            for mmap in mappings:
                if not set(mmap.keys()) == {"aggressor_to_addr", "id", "bit_flips"}:
                    yield NotImplemented
                yield HammeringPatternInstance(self, mmap)

        if not all(isinstance(x, AggressorAccessPattern) for x in aggr_list):
            raise Exception("Not all elements are of AggressorAccessPattern type")

        self.uid = uid
        self.base_period = base_period
        self.max_period = max_period
        self.aggr_list = aggr_list
        self.order = order
        self.instances = InstanceList((inst for inst in gen_instances(mappings)))

    def __str__(s):
        col_fn = col_green if any([x.flips for x in s.instances]) else col_red
        return f"HammPatt[{col_fn(s.uid)}]( #aggr_tuples: {len(s.aggr_list)}, period (base/max): {s.base_period}/{s.max_period})"

    def __repr__(self):
        return self.__str__()


class HammeringPatternInstance():

    def __init__(self, shape, mapp):

        def parse_mapper(llist):
            return {int(a[0]): DRAMAddr.from_json(a[1]) for a in llist}

        def parse_flips(llist):
            return [BitFlip.from_json(x) for x in llist]

        def interpolate_flip(flip):
            dist = lambda tup, flp: min(map(lambda x: abs(flp.addr.row - x.row), tup.aggr_tuple))
            min_dist = min((dist(tup, flip) for tup in self.aggr_list))
            # print(self.uid, ": ", min_dist)
            # assert min_dist < 5, "No AggressorAccessPattern respects the max distance"
            for tup in self.aggr_list:
                dista = dist(tup, flip)
                if dista == min_dist:
                    tup.attach_flip(flip)

        shape_dict = vars(shape)

        for k in shape_dict:
            if k in ['uid', 'instances']:
                continue
            setattr(self, k, shape_dict[k])

        address_dict = parse_mapper(mapp['aggressor_to_addr'])
        self.flips = parse_flips(mapp['bit_flips'])
        self.uid = mapp['id']

        self.order = [address_dict[x] for x in self.order]
        self.aggr_list = [x.map_it(address_dict) for x in self.aggr_list]
        for flp in self.flips:
            interpolate_flip(flp)

    def __repr__(s):
        return s.__str__()

    def __str__(s):
        aggr_str = "\n" + pp.pformat(s.aggr_list, indent=4)
        col_fn = col_green if len(s.flips) else col_red
        return f"HammInst[{col_fn(s.uid)}]({aggr_str})"

    def to_signal(s):
        return list(enumerate(s.order))

    def time_plot(self, dest_filepath: str = None, plot_subtitle: str = None):
        print('[+] Generating time plot.')
        plt.rc('text', usetex=True)

        fig, axes = plt.subplots(len(self.aggr_list), 1, sharex='all', constrained_layout=True)
        fig.set_figheight(7)
        for tup, ax in zip(self.aggr_list, axes):
            tup.to_time_plot(ax, self.max_period)

        # hackish way to set the x_labels to match the periods so that it's easy to see the frequencies 
        tmp_ax = axes[0]
        tmp_ax.set_xticks(range(0, self.max_period + 1, self.base_period))
        tmp_ax.set_xlim(-1, self.max_period + 1)

        fig.suptitle(f'{self.uid}')
        if plot_subtitle is not None:
            fig.suptitle(f"{self.uid}"
                         "\n{\\small{"
                         f"{plot_subtitle}"
                         "}")
        plt.xlabel("Time")

        if dest_filepath is None:
            plt.show()
        else:
            plt.savefig(os.path.join(dest_filepath, "plot_time.png"), dpi=180)

        plt.close()

    def freq_ampl_plot(self, dest_filepath: str = None, plot_subtitle: str = None):
        def autolabel(ax, rect, label):
            height = rect.get_height()
            ax.annotate(f'{label}',
                        xy=(rect.get_x() + rect.get_width() / 2, height),
                        xytext=(0, 3),  # 3 points vertical offset
                        textcoords="offset points",
                        ha='center', rotation=90, va='bottom', fontsize=8)

        def gen_legend():
            return [Line2D([0], [0], color='C0', lw=4, label='No Flips'),
                    Line2D([0], [0], color='C1', lw=4, label='Flips')]

        print('[+] Generating frequency/amplitude plot.')
        data = pd.DataFrame([x.to_pandas_entry(self.max_period) for x in self.aggr_list])
        data.sort_values(["frequency", "amplitude"], inplace=True)
        fig, ax = plt.subplots()
        fig.set_figheight(7)

        for k, g in data.groupby("frequency"):
            off = [x / 10 for x in range(1, len(g))]
            if len(off) > 1:
                max_off = max(off)
                off = [k - max_off / 2 + x for x in off]
            else:
                off = [k]
            for x, (_, v) in zip(off, g.iterrows()):
                bb = ax.bar(x, v["amplitude"], width=0.09, color="C0" if not v['flips'] else "C1")
                autolabel(ax, bb[0], v['label'])

        ax2 = ax.twiny()
        ax2.set_xticks(ax.get_xticks())
        ax2.set_xticklabels([round(self.max_period / x, 0) if x != 0 else "NaN" for x in ax2.get_xticks()])
        ax2.set_xlim(ax.get_xlim())
        ax2.set_xlabel("Period")

        ax2.set_ylim(ax.get_ylim())

        fig.suptitle(f'{self.uid}')
        if plot_subtitle is not None:
            fig.suptitle(f"{self.uid}"
                         "\n{\\small{"
                         f"{plot_subtitle}"
                         "}")
        ax.set_xlabel("Frequency")
        ax.set_ylabel("Amplitude")
        ax.yaxis.set_major_locator(MaxNLocator(integer=True))
        ax.legend(handles=gen_legend())

        if dest_filepath is None:
            plt.show()
        else:
            plt.savefig(os.path.join(dest_filepath, "plot_freq_amplitude.png"), dpi=180)

        plt.close(fig)

    def freq_phase_plot(self, dest_filepath: str = None, plot_subtitle: str = None):
        def autolabel(ax, rect, label):
            height = rect.get_height()
            ax.annotate(f'{label}',
                        xy=(rect.get_x() + rect.get_width() / 2, height),
                        xytext=(0, 3),  # 3 points vertical offset
                        textcoords="offset points",
                        ha='center', rotation=90, va='bottom')

        def gen_legend():
            return [Line2D([0], [0], color='C0', lw=4, label='No Flips'),
                    Line2D([0], [0], color='C1', lw=4, label='Flips')]

        print('[+] Generating frequency/phase plot.')
        data = pd.DataFrame([x.to_pandas_entry(self.max_period) for x in self.aggr_list])
        fig, ax = plt.subplots()
        ax.scatter(data['frequency'], data['phase'], c=["C0" if r.flips is False else "C1" for x, r in data.iterrows()])

        fig.suptitle(f'{self.uid}', y=0.96)
        if plot_subtitle is not None:
            plt.title(plot_subtitle, fontsize=9)

        ax.set_xlabel("Frequency")
        ax.set_ylabel("Phase")
        ax.legend(handles=gen_legend())

        if dest_filepath is None:
            plt.show()
        else:
            plt.savefig(os.path.join(dest_filepath, "plot_freq_phase.png"), dpi=180)

        plt.close(fig)
