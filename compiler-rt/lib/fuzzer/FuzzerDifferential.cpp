#include "FuzzerDifferential.h"

#include "FuzzerIO.h"
#include "FuzzerSHA1.h"

#include <algorithm>
#include <fstream>
#include <iostream>
#include <map>
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

uint32_t hashVector(const fuzzer::Unit &vec) {
  uint32_t seed = vec.size();
  for (auto x : vec) {
    seed = hashInt(x, seed);
  }
  return seed;
}

struct Comparer {
  int operator()(const fuzzer::Unit &u0, const fuzzer::Unit &u1) {
    return hashVector(u0) < hashVector(u1);
  }
};

static std::map<fuzzer::Unit, std::vector<fuzzer::BatchResult>, Comparer>
    ProcessedInputs;

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
    size += fuzzer::TPC.Modules[i].Size();
  }

  std::cerr << "Registered '" << std::string(id) << "' with "
            << std::to_string(size) << " edges" << std::endl;

  this->targets.push_back({id, modules, pctables});
}

void DTManager::startBatch(const uint8_t *Data, size_t Size) {
  this->inputData = {Data, Data + Size};

  this->batchResult.ExitCode = std::vector<int>(this->targets.size());
  this->batchResult.Output = std::vector<Unit>(this->targets.size());
  this->batchResult.PDCoarse = std::vector<int>(this->targets.size());
  this->batchResult.PCFine = std::vector<int>(this->targets.size());
  this->batchResult.DEBUG_edges = std::vector<uintptr_t>();
  this->interestingState = false;
}

void printMismatch(const std::vector<BatchResult> &results) {
  std::vector<int> exitCodesHashes;
  std::vector<int> coarseTupleHashes;
  std::vector<int> fineTupleHashes;

  for (int i = 0; i < results.size(); i++) {
    exitCodesHashes.push_back(hashVector(results[i].ExitCode));
    coarseTupleHashes.push_back(hashVector(results[i].PDCoarse));
    fineTupleHashes.push_back(hashVector(results[i].PCFine));
  }

  auto size = [&]() {
    if (results.size() == 0) {
      std::cerr << "Error: Results size is 0" << std::endl;
      exit(1);
    }

    int width = results.size();
    int height = results[0].ExitCode.size();

    for (int i = 0; i < results.size(); i++) {
      auto &result = results[i];

      if (height != result.ExitCode.size()) {
        std::cerr << "Error: Height mismatch (" << height << ","
                  << result.ExitCode.size() << ") in item " << i << std::endl;
        exit(1);
      }

      if (height != result.PDCoarse.size()) {
        std::cerr << "Error: Height mismatch (" << height << ","
                  << result.PDCoarse.size() << ") in item " << i << std::endl;
        exit(1);
      }

      if (height != result.PCFine.size()) {
        std::cerr << "Error: Height mismatch (" << height << ","
                  << result.PCFine.size() << ") in item " << i << std::endl;
        exit(1);
      }
    }

    return std::make_pair(width, height);
  }();
  int n_batchresults = size.first;
  int n_targets = size.second;

  //
  // EXIT CODES:
  //

  [&]() {
    std::set<int> uniqueExitCodeHashes(exitCodesHashes.begin(),
                                       exitCodesHashes.end());

    if (uniqueExitCodeHashes.size() <= 1) {
      return;
    }

    std::cout << "Exit codes differ: " << std::endl;

    for (int j = 0; j < n_targets; j++) {
      std::cout << "\t" << j << ": ";
      for (int i = 0; i < n_batchresults; i++) {
        std::cout << results[i].ExitCode[j];
        if (i < n_batchresults - 1) {
          std::cout << ",";
        }
      }

      std::set<int> exitCodes;
      for (int i = 0; i < n_batchresults; i++) {
        exitCodes.insert(results[i].ExitCode[j]);
      };

      if (exitCodes.size() > 1) {
        std::cout << " <-";
      }

      std::cout << "\n";
    }
  }();

#ifdef ANALYSE_COVERAGE_MISMATCH
  /*
   * Edges have weird hex-decimal addresses. We map each of the addresses to a
   * smaller number.
   *
   * 0x1435463, 0x32643, 0x1435463, 0x2523623 => 0, 1, 0, 2
   */
  std::map<uintptr_t, int> edgeNormalizer;

  // TODO: Write normalized edges as debug information
  // Fill normalize
  {
    for (auto &result : results) {
      for (auto &edge : result.DEBUG_edges) {
        if (edgeNormalizer.find(edge) != edgeNormalizer.end()) {
          edgeNormalizer.insert(std::make_pair(edge, edgeNormalizer.size()));
        }
      }
    }
  }
#endif

  [&]() {
    std::set<int> uniquePDCoarseHashes(coarseTupleHashes.begin(),
                                       coarseTupleHashes.end());

    if (uniquePDCoarseHashes.size() <= 1) {
      return;
    }

    std::cout << "Coarse tuple differ: " << std::endl;

    for (int j = 0; j < n_targets; j++) {
      std::cout << "\t" << j << ": ";
      for (int i = 0; i < n_batchresults; i++) {
        std::cout << results[i].PDCoarse[j];
        if (i < n_batchresults - 1) {
          std::cout << ",";
        }
      }

      std::set<int> pdCoarse;
      for (int i = 0; i < n_batchresults; i++) {
        pdCoarse.insert(results[i].PDCoarse[j]);
      };

      if (pdCoarse.size() > 1) {
        std::cout << " <-";
      }

      std::cout << "\n";
    }
  }();

  [&]() {
    std::set<int> uniquePCFineHashes(fineTupleHashes.begin(),
                                     fineTupleHashes.end());

    if (uniquePCFineHashes.size() <= 1) {
      return;
    }

    std::cout << "Fine tuple differ: " << std::endl;

    for (int j = 0; j < n_targets; j++) {
      std::cout << "\t" << j << ": ";
      for (int i = 0; i < n_batchresults; i++) {
        std::cout << results[i].PCFine[j];
        if (i < n_batchresults - 1) {
          std::cout << ",";
        }
      }

      std::set<int> pcFine;
      for (int i = 0; i < n_batchresults; i++) {
        pcFine.insert(results[i].PCFine[j]);
      };

      if (pcFine.size() > 1) {
        std::cout << " <-";
      }

      std::cout << "\n";
    }
  }();
}

void DTManager::endBatch() {
  bool allParsersReject = std::all_of(
      this->batchResult.ExitCode.begin(), this->batchResult.ExitCode.end(),
      [](int exit_code) { return exit_code != 0; });

  if (allParsersReject) {
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

  this->interestingState |= exitCodesIter.second;
  this->interestingState |= coarseTupleIter.second;
  this->interestingState |= fineTupleIter.second;

  auto newTuple = [&]() {
    int hash = 0;
    hash = hashInt(*exitCodesIter.first, hash);
    hash = hashInt(*coarseTupleIter.first, hash);
    hash = hashInt(*fineTupleIter.first, hash);
    return this->cumResult.TupleHashes.insert(hash);
  }();

  bool isNewTuple = newTuple.second;
  if (!isNewTuple) {
    return;
  }

  std::set<std::string> outputs;
  for (auto &s : this->batchResult.Output) {
    outputs.insert({s.begin(), s.end()});
  }

  if (outputs.size() == 1) {
    return;
  }

  {
    std::vector<Unit> relevantOutputs;

    for (int i = 0; i < this->batchResult.ExitCode.size(); i++) {
      if (this->batchResult.ExitCode[i] == 0) {
        relevantOutputs.push_back(this->batchResult.Output[i]);
      }
    }

    std::string classPrefix = assignClass(this->inputData, relevantOutputs);

    if (classPrefix.size() > 0) {
      return;
    }

    std::stringstream ss;
    ss << "output/diffs-summary/" << classPrefix << "diff-" << outputs.size()
       << "-" << *exitCodesIter.first << "-" << *coarseTupleIter.first << "-"
       << *fineTupleIter.first << "-" << fuzzer::Hash(this->inputData)
       << ".txt";
    std::string filename = ss.str();

    std::cout << "Summary file: " << filename << std::endl;
    fuzzer::WriteToFile(this->inputData, filename);

    {
      std::ofstream f(filename, std::ios::out);
      f << std::string(this->inputData.begin(), this->inputData.end()) << "\n";
      for (int i = 0; i < this->batchResult.Output.size(); i++) {
        f << this->targets[i].identifier
          << " (Exit Code: " << this->batchResult.ExitCode[i]
          << " - Size: " << this->batchResult.Output[i].size() << "): ";
        for (int j = 0; j < this->batchResult.Output[i].size(); j++) {
          if (std::isprint(this->batchResult.Output[i][j])) {
            f << this->batchResult.Output[i][j];
          } else {
            f << " [" << std::to_string(this->batchResult.Output[i][j]) << "] ";
          }
        }
        f << "\n";
      }
    }
  }

  {
    std::stringstream ss;
    ss << "output/diffs/diff-" << outputs.size() << "-" << *exitCodesIter.first
       << "-" << *coarseTupleIter.first << "-" << *fineTupleIter.first << "-"
       << fuzzer::Hash(this->inputData);
    std::string filename = ss.str();
    fuzzer::WriteToFile(this->inputData, filename);
  }

#ifdef CHECK_FOR_COVERAGE_MISMATCH
  auto it = ProcessedInputs.find(this->inputData);
  if (it == ProcessedInputs.end()) {
    std::vector<BatchResult> vec = {this->batchResult};
    ProcessedInputs.insert(std::make_pair(this->inputData, vec));
  } else {
    auto &vec = it->second;
    vec.push_back(this->batchResult);

    if (vec.size() > 1) {
      printMismatch(vec);
      std::cout << "Mismatch input:"
                << std::string(this->inputData.begin(), this->inputData.end())
                << std::endl;
    }
  }
#endif
}

void DTManager::startRun(int targetIndex) {}

void DTManager::endRun(int targetIndex, int exit_code,
                       const uint8_t *OutputData, size_t OutputSize) {
  auto &target = this->targets[targetIndex];
  auto &modules = target.modules;

  this->batchResult.ExitCode[targetIndex] = exit_code;
  this->batchResult.Output[targetIndex] =
      Unit(OutputData, OutputData + OutputSize);

  int edgeHash = 0;

  for (int moduleIndex = modules.start; moduleIndex < modules.end;
       moduleIndex++) {
    auto &m = TPC.Modules[moduleIndex];

    for (uint8_t *edge = m.Start(); edge < m.Stop(); edge++) {
      if (*edge) {
#ifdef ANALYSE_COVERAGE_MISMATCH
        if (targetIndex == DEBUG_INDEX) {
          this->batchResult.DEBUG_edges.push_back(
              reinterpret_cast<std::uintptr_t>(edge));
        }
#endif

        this->batchResult.PDCoarse[targetIndex] += *edge;
        edgeHash = hashInt(reinterpret_cast<std::uintptr_t>(edge), edgeHash);
      }
    }
  }

  this->batchResult.PCFine[targetIndex] = edgeHash;
}

bool DTManager::isInterestingRun() const { return this->interestingState; }
} // namespace fuzzer