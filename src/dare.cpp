#include <argagg.hpp>
#include <iostream>
#include <optional>

#include "analyzer.hpp"
#include "solver.hpp"
#include "utils.hpp"

struct {
    size_t num_superpages { 0 };
    size_t num_clusters { 0 };
    std::optional<uint64_t> row_conflict_threshold;
    size_t address_offset_mb { 0 };
    bool log_verbose { false };
    std::optional<std::string> hist_out_file;
    std::optional<std::string> out_file;
} args;

void parse_args(int argc, char** argv) {
    argagg::parser parser { { { "help", { "-h", "--help" }, "show help", 0 },
        { "superpages", { "--superpages" }, "number of superpages to allocate", 1 },
        { "clusters", { "--clusters" }, "expected number of clusters (i.e., channels * ranks * bank groups * banks * ...)", 1 },
        { "threshold", { "--threshold" }, "row conflict threshold (in cycles, default: auto)", 1 },
        { "offset", { "--offset" }, "offset between physical and DRAM addresses (in MiB, default: 0)", 1 },
        { "hist_out", { "--hist-out" }, "file to histgram data to (in CSV format)", 1 },
        { "out", { "--out" }, "file to save clusters to (in CSV format)", 1 },
        { "verbose", { "-v", "--verbose" }, "be verbose", 0 } } };

    argagg::parser_results parsed_args;
    try {
        parsed_args = parser.parse(argc, argv);
    } catch (std::exception const& e) {
        std::cerr << e.what() << std::endl;
        exit(EXIT_FAILURE);
    }

    if (parsed_args["help"]) {
        std::cerr << parser << std::endl;
        exit(EXIT_SUCCESS);
    }

    // Mandatory arguments.
    if (!parsed_args.has_option("superpages")) {
        LOG_ERROR("Error: Argument '--superpages' is required.\n");
        exit(EXIT_FAILURE);
    }
    args.num_superpages = parsed_args["superpages"].as<size_t>();

    if (!parsed_args.has_option("clusters")) {
        LOG_ERROR("Error: Argument '--clusters' is required.\n");
        exit(EXIT_FAILURE);
    }
    args.num_clusters = parsed_args["clusters"].as<size_t>();

    if (parsed_args.has_option("threshold")) {
        args.row_conflict_threshold.emplace(parsed_args["threshold"].as<uint64_t>());
    }

    if (parsed_args.has_option("offset")) {
        args.address_offset_mb = parsed_args["offset"].as<uint64_t>();
    } else {
        args.address_offset_mb = 0;
    }

    if (parsed_args.has_option("hist_out")) {
        if (args.row_conflict_threshold.has_value()) {
            LOG_ERROR("Error: Arguments '--threshold' and '--hist-out' are incompatible.");
            exit(EXIT_FAILURE);
        }
        args.hist_out_file.emplace(parsed_args["hist_out"].as<std::string>());
    }

    if (parsed_args.has_option("out")) {
        args.out_file.emplace(parsed_args["out"].as<std::string>());
    }

    args.log_verbose = parsed_args.has_option("verbose");
}

int main(int argc, char** argv) {
    parse_args(argc, argv);
    log_verbose = args.log_verbose;

    analyzer analyzer(args.num_superpages);
    if (args.row_conflict_threshold) {
        analyzer.set_row_conflict_threshold(*args.row_conflict_threshold);
    } else {
        analyzer.find_row_conflict_threshold(args.num_clusters, args.hist_out_file);
    }
    analyzer.build_clusters(args.num_clusters);

    if (args.out_file.has_value()) {
        analyzer.dump_clusters(*args.out_file);
    }

    solver solver(analyzer.clusters());
    (void)solver.find_bank_functions(args.address_offset_mb * MiB);
    return 0;
}
