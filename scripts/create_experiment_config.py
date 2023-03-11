#!/usr/bin/env python3
from __future__ import annotations
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import ClassVar, List
from itertools import product
from itertools import combinations

import yaml


class ExecutionMode(Enum):
    ALTERNATING = "ALTERNATING"
    BATCHED = "BATCHED"


@dataclass
class RowOrigin():
    same_bg: bool
    same_bk: bool


@dataclass
class ExperimentConfig:
    config_id: int = field(init=False)
    config_id_cnt: ClassVar[List["ExperimentConfig"]] = []
    execution_mode: str
    row_distance: int
    num_sync_rows: int
    num_measurement_rounds: int
    row_origin: RowOrigin

    def __post_init__(self: "ExperimentConfig") -> None:
        self.config_id = len(self.config_id_cnt)
        self.config_id_cnt.append(self)


def main():
    print("Generating configurations...")
    exp_cfgs = list()
    for exec_mode in [ExecutionMode.BATCHED, ExecutionMode.ALTERNATING]:
        for ro in product([True,False], repeat=2):
            # for row_dist in range(1, 3):
            for row_dist in [3]:

                if ro != (True, True) and row_dist > 1:
                    continue

                # for n_sync_rows in [2,4]:
                for n_sync_rows in [8,16,32,64,122]:

                    if n_sync_rows == 1 and exec_mode == ExecutionMode.BATCHED:
                        continue

                    for n_msmt_rnds in [5000, 50_000]:
                        exp_cfgs.append(ExperimentConfig(
                            execution_mode=exec_mode.value,
                            row_distance=row_dist,
                            num_sync_rows=n_sync_rows,
                            num_measurement_rounds=n_msmt_rnds,
                            row_origin=RowOrigin(same_bg=ro[0], same_bk=ro[1])))
    print("#configurations =", len(exp_cfgs))

    # print("---")
    # print(yaml.safe_dump({'experiment_configs': [asdict(x) for x in exp_cfgs]}))
    # print("---")

    print("Writing YAML into file...")
    with open("exp_config.yaml", "w") as f:
        f.write(yaml.safe_dump({'experiment_configs': [asdict(x) for x in exp_cfgs]}))




if __name__ == "__main__":
    main()
