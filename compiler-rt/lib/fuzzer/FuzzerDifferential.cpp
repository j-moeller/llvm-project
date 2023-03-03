#include "FuzzerDifferential.h"

#include "FuzzerIO.h"
#include "FuzzerSHA1.h"
#include "FuzzerUtil.h"

#include <cmath>
#include <fstream>
#include <iostream>
#include <map>
#include <numeric>
#include <regex>

namespace fuzzer {

DTManager DTM;
extern TracePC TPC;

uint32_t hashInt(uint32_t x, uint32_t seed) {
  x = ((x >> 16) ^ x) * 0x45d9f3b;
  x = ((x >> 16) ^ x) * 0x45d9f3b;
  x = (x >> 16) ^ x;
  seed ^= x + 0x9e3779b9 + (seed << 6) + (seed >> 2);

  return seed;
}

uint32_t hashVector(const std::vector<int> &vec) {
  uint32_t seed = vec.size();
  for (auto x : vec) {
    seed = hashInt(x, seed);
  }
  return seed;
}

uint32_t hashVector(const Unit &vec) {
  uint32_t seed = vec.size();
  for (auto x : vec) {
    seed = hashInt(x, seed);
  }
  return seed;
}

uint32_t hashUnitVector(const Unit &vec) { return hashVector(vec); }

struct Comparer {
  int operator()(const Unit &u0, const Unit &u1) {
    return hashVector(u0) < hashVector(u1);
  }
};

static std::map<Unit, std::vector<BatchResult>, Comparer> ProcessedInputs;

} // namespace fuzzer

// TODO: Make sure that LLVMFuzzerStartRegistration and
// LLVMFuzzerEndRegistration are called with the same identifier
static int n_modules = 0;
static int n_pctables = 0;

extern "C" {
void LLVMFuzzerStartRegistration(const char *) {
  n_modules = fuzzer::DTM.getNumberOfModules();
  n_pctables = fuzzer::DTM.getNumberOfPCTables();
}
void LLVMFuzzerEndRegistration(const char *id) {
  fuzzer::DTM.registerProgramCoverage(
      id, {n_modules, fuzzer::DTM.getNumberOfModules()},
      {n_pctables, fuzzer::DTM.getNumberOfPCTables()});
}
void LLVMFuzzerStartBatch(const uint8_t *Data, size_t Size) {
  fuzzer::DTM.startBatch(Data, Size);
}
void LLVMFuzzerEndBatch() { fuzzer::DTM.endBatch(); }
void LLVMFuzzerStartRun(int i) { fuzzer::DTM.startRun(i); }
void LLVMFuzzerEndRun(int i, int exit_code, const uint8_t *data, size_t size) {
  fuzzer::DTM.endRun(i, exit_code, data, size);
}
}

namespace fuzzer {

[[nodiscard]] double calculateOutputEntropy(const BatchResult &batchResult,
                                            int n_targets) {
  /**
   * Idea:
   *
   * Implement a histogram over the output strings of each program, e.g. an
   * output "aaabb" would be mapped to the vector h_i = [3, 2, 0, ..., 0]
   *
   * If we run multiple programs on the same input, we expect similar output
   * vectors. We can display these vectors in a matrix:
   *
   * h_0 = [0, 5, ..., 2]
   * h_1 = [1, 0, ..., 1]
   * h_2 = [0, 2, ..., 0]
   * h_3 = [0, 5, ..., 2]
   *
   * The objective of our fuzzing campaign should be to make these rows as
   * dissimilar as possible, i.e. we want to make each parser interpret the
   * input differently. We could choose multiple ways to measure similarity
   * between the rows. A fast and efficient way (that does not require O(n^2))
   * is to calculate a hash for each row:
   *
   * h_0 = [0, 5, ..., 2] => a
   * h_1 = [1, 0, ..., 1] => b
   * h_2 = [0, 2, ..., 0] => c
   * h_3 = [0, 5, ..., 2] => a
   *
   * We can then definer the entropy for each row as:
   *      -(log_2(p_a) * p_a + log_2(p_b) * p_b + log_2(p_c) * p_c)
   *
   * where p_x is the frequency of hash 'x'.
   *
   * TODO: Can we 'stack' the histograms horizontally to determine a change in
   * entropy and measure how similar to histograms (=> and their inputs) are?
   *
   */

  const auto &outputs = batchResult.Output;

  /*
   * Calculate hashes over output and exit code
   */
  std::vector<uint32_t> hashes;
  {
    std::transform(outputs.begin(), outputs.end(), back_inserter(hashes),
                   hashUnitVector);
    for (int i = 0; i < n_targets; i++) {
      hashes[i] = hashInt(batchResult.ExitCode[i], hashes[i]);
    }
  }

  /*
   * Create a histogram over the hashes
   */
  std::map<uint32_t, int> histogram;
  for (auto &hash : hashes) {
    auto it = histogram.find(hash);
    if (it == histogram.end()) {
      histogram.insert(std::make_pair(hash, 1));
    } else {
      it->second++;
    }
  }

  /**
   * Calculate entropy:
   *                 -\sum_i log_2(p_i) * p_i
   *  = -(1/log(2)) * \sum_i log(p_i) * p_i
   *
   * where p_i is the frequency of a hash in the histogram.
   */
  double entropy = 0;
  for (auto it : histogram) {
    double value = it.second;
    double p_i = value / n_targets;

    entropy += std::log(p_i) / std::log(2) * p_i;
  }

  return -entropy;
}

void dumpTopEntropies(std::map<double, Unit> &topEntropies, int n_targets) {
  static int counter = 0;
  counter++;

  if (counter % 10000 == 0) {
    /**
     * Max entropy:
     *    -\sum_i log_2(p) * p
     *  = -n * log_2(p) * p
     */
    {
      double n = n_targets;
      double p = 1 / n;

      std::string path = "output/diffs-top-entropy/";
      std::ofstream f(path + "meta.txt", std::ios::out);
      f << "Max Entropy for " << n
        << " targets: " << (-n * std::log(p) / std::log(2) * p) << "\n";

      int rank = topEntropies.size();
      for (auto &it : topEntropies) {
        std::string filename = path + std::to_string(rank) + ".txt";
        WriteToFile(it.second, filename);
        f << rank << ": " << it.first << "\n";
        rank--;
      }
    }
  }
}

bool atLeastOneParserAccepts(const BatchResult &br) {
  auto sum = [](const int &acc, const int &v) {
    return (v == 0) ? acc + 1 : acc;
  };
  int n_success_exits =
      std::accumulate(br.ExitCode.begin(), br.ExitCode.end(), 0, sum);

  return n_success_exits > 0;
}

void updateTopEntropies(std::map<double, Unit> &topEntropies,
                        const BatchResult &br, int n_targets) {
  if (isNumberOnlyClass(br.inputData, br.Output)) {
    return;
  }

  double entropy = calculateOutputEntropy(br, n_targets);
  int max_size = 10;
  if (topEntropies.size() == 0) {
    topEntropies.insert(std::make_pair(entropy, br.inputData));
  } else {
    auto it = topEntropies.lower_bound(entropy);
    topEntropies.insert(it, std::make_pair(entropy, br.inputData));
    if (topEntropies.size() > max_size) {
      topEntropies.erase(topEntropies.begin());
    }
  }
}

bool isTrailingGarbageClass(const Unit &input,
                            const std::vector<Unit> &outputs) {
  for (auto &output : outputs) {
    int size = (output.size() < input.size()) ? output.size() : input.size();
    bool isPrefix = true;
    for (int i = 0, j = 0; i < size; i++) {
      if (input[i] == 0x20 || input[i] == 0x0a || input[i] == 0x0d ||
          input[i] == 0x09) {
        continue;
      }

      if (input[i] != output[j]) {
        isPrefix = false;
        break;
      }

      j++;
    }
    if (isPrefix) {
      return true;
    }
  }

  return false;
}

bool isAddsCommaClass(const Unit &input, const std::vector<Unit> &outputs) {
  int n_commas = std::count(input.begin(), input.end(), ',');
  for (auto &output : outputs) {
    int n_commas_output = std::count(output.begin(), output.end(), ',');
    if (n_commas < n_commas_output) {
      return true;
    }
  }

  return false;
}

bool isContainsUnicodeEscapeClass(const Unit &input,
                                  const std::vector<Unit> &outputs) {
  auto it = std::find(input.begin(), input.end(), '\\');
  if (it == input.end()) {
    return false;
  }
  it++;
  if (it == input.end()) {
    return false;
  }
  return *it == 'u';
}

bool isAddsQuotesClass(const Unit &input, const std::vector<Unit> &outputs) {
  int n_quotes = std::count(input.begin(), input.end(), '"');
  for (auto &output : outputs) {
    int n_quotes_output = std::count(output.begin(), output.end(), '"');
    if (n_quotes > n_quotes_output) {
      return true;
    }
  }

  return false;
}

bool isRemovesCommaClass(const Unit &input, const std::vector<Unit> &outputs) {
  int n_commas = std::count(input.begin(), input.end(), ',');
  for (auto &output : outputs) {
    int n_commas_output = std::count(output.begin(), output.end(), ',');
    if (n_commas > n_commas_output) {
      return true;
    }
  }

  return false;
}

bool isNumberOnlyClass(const Unit &input, const std::vector<Unit> &outputs) {
  // clang-format off
  static const std::regex NUMBERS_REGEX(
      "^\\s*"
      "(-)?"                // sign (1)
      "(0|[1-9]?[0-9]+)"    // integer (2) (required)
      "("                   // (3)
          "\\."               
          "("                   // fraction (4) (required if frac)
              "(0*)"            // fraction-zeros (5)
              "([0-9]+)"        // fraction-rest (6) (required if frac)
          ")"
      ")?"  
      "("                   // exponent (7)
          "([eE])"              // exponent-indicator (8) (required if exp)
          "(-|\\+)?"            // exponent-sign (9)
          "([0-9]+)"            // exponent-value (10) (required if exp)
      ")?"
      "\\s*$"
  );
  // clang-format on

  std::smatch capture_groups;
  std::string s(input.begin(), input.end());
  return std::regex_search(s, capture_groups, NUMBERS_REGEX);
}

bool isStringOnlyClass(const Unit &input, const std::vector<Unit> &outputs) {
  if (input.size() < 2) {
    return false;
  }

  // Find first quote character
  auto it = std::find(input.begin(), input.end(), '"');
  if (it == input.end()) {
    return false;
  }

  // Find second quote character
  auto it2 = std::find(it, input.end(), '"');
  if (it == input.end()) {
    return false;
  }

  // If the second quote character is located at the end, we found a string-only
  // input.
  return ++it == input.end();
}

std::string assignClass(const Unit &input, const std::vector<Unit> &outputs) {
  if (isNumberOnlyClass(input, outputs)) {
    return "number-only";
  }

  if (isStringOnlyClass(input, outputs)) {
    return "string-only";
  }

  if (isAddsCommaClass(input, outputs)) {
    return "adds-comma-";
  }

  if (isContainsUnicodeEscapeClass(input, outputs)) {
    return "contains-unicode-escape-";
  }

  if (isAddsQuotesClass(input, outputs)) {
    return "adds-quotes";
  }

  if (isRemovesCommaClass(input, outputs)) {
    return "removes-comma";
  }

  if (isTrailingGarbageClass(input, outputs)) {
    return "is-trailing-garbage-";
  }

  return "";
}

int DTManager::getNumberOfModules() const { return TPC.NumModules; }

int DTManager::getNumberOfPCTables() const { return TPC.NumPCTables; }

void DTManager::registerProgramCoverage(std::string id, Range modules,
                                        Range pctables) {
  int size = 0;
  for (int i = modules.start; i < modules.end; i++) {
    size += TPC.Modules[i].Size();
  }

  int n_pctables = 0;
  for (int i = pctables.start; i < pctables.end; i++) {
    n_pctables += TPC.ModulePCTable[i].Stop - TPC.ModulePCTable[i].Start;
  }

  assert(size == n_pctables);

  std::cerr << "Registered '" << std::string(id) << "' with "
            << std::to_string(size) << " edges" << std::endl;

  this->targets.push_back({id, modules, pctables});
}

void DTManager::startBatch(const uint8_t *Data, size_t Size) {
  this->batchResult.inputData = {Data, Data + Size};

  this->batchResult.ExitCode = std::vector<int>(this->targets.size());
  this->batchResult.Output = std::vector<Unit>(this->targets.size());
  this->batchResult.PDCoarse = std::vector<int>(this->targets.size());
  this->batchResult.PCFine = std::vector<int>(this->targets.size());
  this->batchResult.edges =
      std::vector<std::vector<EdgeCoverage>>(this->targets.size());
  this->interestingState = false;
}

void DTManager::endBatch() {
  static std::map<double, Unit> topEntropies;

  dumpTopEntropies(topEntropies, this->targets.size());

  if (!atLeastOneParserAccepts(this->batchResult)) {
    return;
  }

  auto hashAndInsert = [&](const std::vector<int> &vec,
                           std::set<uint32_t> &set) {
    uint32_t hash = hashVector(vec);
    return set.insert(hash);
  };

  auto exitCodesIter =
      hashAndInsert(this->batchResult.ExitCode, this->cumResult.ExitCodeHashes);

  auto coarseTupleIter =
      hashAndInsert(this->batchResult.PDCoarse, this->cumResult.PDCoarseHashes);

  auto fineTupleIter =
      hashAndInsert(this->batchResult.PCFine, this->cumResult.PCFineHashes);

  this->interestingState &= exitCodesIter.second;
  this->interestingState &= coarseTupleIter.second;
  this->interestingState &= fineTupleIter.second;

  updateTopEntropies(topEntropies, this->batchResult, this->targets.size());
}

void DTManager::startRun(int targetIndex) {}

void DTManager::endRun(int targetIndex, int exit_code,
                       const uint8_t *OutputData, size_t OutputSize) {
  auto &target = this->targets[targetIndex];
  auto &modules = target.modules;
  auto &pctables = target.pctables;

  assert(modules.end - modules.start == pctables.end - pctables.start);
  const int n_modules = modules.end - modules.start;

  /*
   * Exit code
   */
  this->batchResult.ExitCode[targetIndex] = exit_code;

  /*
   * (string) Output
   */
  this->batchResult.Output[targetIndex] =
      Unit(OutputData, OutputData + OutputSize);

  /*
   * Edges
   * PDCoarse
   * PCFine
   */
  int edgeHash = 0;

  for (int i = 0; i < n_modules; i++) {
    auto moduleIndex = modules.start + i;
    auto pctableIndex = pctables.start + i;

    auto &module = TPC.Modules[moduleIndex];
    auto &pctable = TPC.ModulePCTable[pctableIndex];

    const int n_edges = module.Size();
    assert(n_edges == pctable.Stop - pctable.Start);

    for (size_t r = 0; r < module.NumRegions; r++) {
      auto &region = module.Regions[r];
      if (!region.Enabled) {
        continue;
      }
      for (uint8_t *edge = region.Start; edge < region.Stop; edge++) {
        if (*edge) {
          int edgeIdx = module.Idx(edge);
          auto *entry = &pctable.Start[edgeIdx];

          this->batchResult.edges[targetIndex].push_back(
              {reinterpret_cast<std::uintptr_t>(entry->PC),
               reinterpret_cast<std::uintptr_t>(edge), *edge});

          this->batchResult.PDCoarse[targetIndex] += *edge;
          edgeHash = hashInt(reinterpret_cast<std::uintptr_t>(edge), edgeHash);
        }
      }
    }
  }

  this->batchResult.PCFine[targetIndex] = edgeHash;
}

bool DTManager::isInterestingRun() const { return this->interestingState; }
} // namespace fuzzer