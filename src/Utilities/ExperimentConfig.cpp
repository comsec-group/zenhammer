#include "Utilities/ExperimentConfig.hpp"

#include <yaml-cpp/yaml.h>

ExperimentConfig::ExperimentConfig(const std::string &filepath, size_t config_id) : filepath(filepath) {
  YAML::Node config = YAML::LoadFile(filepath);

  for (const auto &cfg : config["experiment_configs"]) {
    if (cfg["config_id"].as<size_t>() == config_id) {
      this->config_id = config_id;
      exec_mode = get_exec_mode_from_string(cfg["execution_mode"].as<std::string>());
      num_measurement_reps = cfg["num_measurement_rounds"].as<size_t>();
      num_sync_rows = cfg["num_sync_rows"].as<size_t>();
      row_distance = cfg["row_distance"].as<size_t>();
      row_origin_same_bg = cfg["row_origin"]["same_bg"].as<bool>();
      row_origin_same_bk = cfg["row_origin"]["same_bk"].as<bool>();
      break;
    }
  }
}

ExperimentConfig::ExperimentConfig(execution_mode ExecMode,
                                   size_t NumMeasurementReps,
                                   size_t NumMeasurementRounds,
                                   size_t NumAccessesPerRound,
                                   size_t NumSyncRows,
                                   size_t RowDistance,
                                   size_t MinRefThresh,
                                   bool RowOriginSameBg,
                                   bool RowOriginSameBk)
    : config_id(0), exec_mode(ExecMode), num_measurement_rounds(NumMeasurementRounds), num_measurement_reps(NumMeasurementReps), num_accesses_per_round(NumAccessesPerRound), num_sync_rows(NumSyncRows),
      row_distance(RowDistance), min_ref_thresh(MinRefThresh), row_origin_same_bg(RowOriginSameBg), row_origin_same_bk(RowOriginSameBk) {
}
